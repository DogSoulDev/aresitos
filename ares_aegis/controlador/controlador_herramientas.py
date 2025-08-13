# -*- coding: utf-8 -*-

import subprocess
from ares_aegis.modelo.modelo_utilidades_sistema import ModeloUtilidadesSistema

class ControladorHerramientas:
    
    def __init__(self, modelo_principal):
        self.modelo_principal = modelo_principal
        self.utilidades_sistema = ModeloUtilidadesSistema()
    
    def verificar_herramientas_disponibles(self):
        return self.utilidades_sistema.verificar_herramientas_kali_completo()
    
    def verificar_herramienta_especifica(self, nombre_herramienta):
        try:
            resultado = subprocess.run(['which', nombre_herramienta], 
                                     capture_output=True, text=True, timeout=5)
            
            if resultado.returncode == 0:
                version = self._obtener_version_herramienta(nombre_herramienta)
                return {
                    'disponible': True,
                    'ruta': resultado.stdout.strip(),
                    'version': version
                }
            else:
                return {'disponible': False, 'error': 'Herramienta no encontrada'}
                
        except Exception as e:
            return {'disponible': False, 'error': str(e)}
    
    def instalar_herramienta(self, nombre_herramienta):
        try:
            resultado = subprocess.run(['apt-get', 'install', '-y', nombre_herramienta],
                                     capture_output=True, text=True, timeout=300)
            
            return {
                'exito': resultado.returncode == 0,
                'salida': resultado.stdout,
                'error': resultado.stderr if resultado.returncode != 0 else None
            }
            
        except subprocess.TimeoutExpired:
            return {'exito': False, 'error': 'Tiempo de instalación agotado'}
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def actualizar_herramientas_sistema(self):
        comandos = [
            ('apt-get', 'update'),
            ('apt-get', 'upgrade', '-y')
        ]
        
        resultados = []
        for comando in comandos:
            try:
                resultado = subprocess.run(comando, capture_output=True, 
                                         text=True, timeout=600)
                resultados.append({
                    'comando': ' '.join(comando),
                    'exito': resultado.returncode == 0,
                    'salida': resultado.stdout[:500],
                    'error': resultado.stderr[:500] if resultado.returncode != 0 else None
                })
            except Exception as e:
                resultados.append({
                    'comando': ' '.join(comando),
                    'exito': False,
                    'error': str(e)
                })
        
        return {'resultados': resultados}
    
    def ejecutar_comando_herramienta(self, herramienta, argumentos):
        try:
            comando = [herramienta] + argumentos
            resultado = subprocess.run(comando, capture_output=True, 
                                     text=True, timeout=60)
            
            return {
                'exito': resultado.returncode == 0,
                'codigo_salida': resultado.returncode,
                'salida': resultado.stdout,
                'error': resultado.stderr if resultado.returncode != 0 else None
            }
            
        except subprocess.TimeoutExpired:
            return {'exito': False, 'error': 'Comando agotó tiempo de ejecución'}
        except FileNotFoundError:
            return {'exito': False, 'error': f'Herramienta {herramienta} no encontrada'}
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def _obtener_version_herramienta(self, herramienta):
        comandos_version = ['--version', '-v', '-V', 'version']
        
        for cmd in comandos_version:
            try:
                resultado = subprocess.run([herramienta, cmd], 
                                         capture_output=True, text=True, timeout=5)
                if resultado.returncode == 0 and resultado.stdout:
                    return resultado.stdout.split('\n')[0]
            except:
                continue
        
        return 'Versión no disponible'

# RESUMEN TÉCNICO: Controlador de gestión de herramientas de Kali Linux. Maneja 
# verificación, instalación y ejecución de herramientas de ciberseguridad. Integración 
# directa con apt-get y comandos del sistema, arquitectura MVC con principios SOLID, 
# sin dependencias externas para administración profesional de herramientas.
