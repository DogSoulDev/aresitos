# -*- coding: utf-8 -*-

import subprocess
import shlex
import logging
import re
from aresitos.modelo.modelo_utilidades_sistema import ModeloUtilidadesSistema
from aresitos.modelo.modelo_reportes import ModeloReportes
from aresitos.modelo.modelo_gestor_wordlists import ModeloGestorWordlists
from aresitos.modelo.modelo_gestor_diccionarios import ModeloGestorDiccionarios

class ControladorUtilidades:
    
    def __init__(self, modelo_principal):
        self.modelo_principal = modelo_principal
        self.utilidades_sistema = ModeloUtilidadesSistema()
        self.reportes = ModeloReportes()
        self.gestor_wordlists = ModeloGestorWordlists()
        self.gestor_diccionarios = ModeloGestorDiccionarios()
        
        # Validaciones de seguridad
        self.comandos_permitidos = {
            'apt-get', 'journalctl', 'find', 'systemctl', 'ps', 'netstat', 'ss'
        }
        self.patron_nombre_seguro = re.compile(r'^[a-zA-Z0-9_-]+$')
        
    def _validar_comando_seguro(self, comando_completo):
        """Valida que el comando sea seguro y esté en whitelist"""
        if not comando_completo:
            return False
            
        # Extraer comando base
        comando_base = comando_completo.split()[0]
        
        # Verificar whitelist
        if comando_base not in self.comandos_permitidos:
            logging.warning(f"Comando no permitido bloqueado: {comando_base}")
            return False
            
        # Verificar caracteres peligrosos
        caracteres_peligrosos = [';', '|', '&', '$(', '`', '<', '>']
        if any(char in comando_completo for char in caracteres_peligrosos):
            logging.warning(f"Comando con caracteres peligrosos bloqueado: {comando_completo}")
            return False
            
        return True
        
    def _validar_nombre_archivo(self, nombre):
        """Valida nombres de archivo/diccionario"""
        if not nombre or not self.patron_nombre_seguro.match(nombre):
            return False
        return True
    
    def verificar_herramientas_disponibles(self):
        return self.utilidades_sistema.verificar_herramientas_kali_completo()
    
    def ejecutar_auditoria_lynis(self):
        return self.utilidades_sistema.ejecutar_auditoria_completa_lynis()
    
    def ejecutar_deteccion_rootkit(self):
        return self.utilidades_sistema.ejecutar_deteccion_rootkits_completa()
    
    def analizar_servicios_activos(self):
        return self.utilidades_sistema.analizar_servicios_sistema_avanzado()
    
    def verificar_permisos_criticos(self):
        return self.utilidades_sistema.verificar_permisos_archivos_criticos_avanzado()
    
    def obtener_informacion_hardware(self):
        return self.utilidades_sistema.obtener_info_hardware_completa()
    
    def ejecutar_limpieza_sistema(self):
        """Ejecuta limpieza del sistema con validación de seguridad"""
        try:
            resultados = []
            # Comandos pre-validados y seguros
            comandos_limpieza = [
                (['apt-get', 'clean'], 'Limpiar cache de paquetes'),
                (['apt-get', 'autoclean'], 'Limpiar paquetes obsoletos'),
                (['journalctl', '--vacuum-time=7d'], 'Limpiar logs antiguos'),
                (['find', '/tmp', '-type', 'f', '-atime', '+7', '-delete'], 'Limpiar archivos temporales')
            ]
            
            for comando_lista, descripcion in comandos_limpieza:
                try:
                    # Validar comando antes de ejecutar
                    comando_str = ' '.join(comando_lista)
                    if not self._validar_comando_seguro(comando_str):
                        resultados.append({
                            'comando': comando_str,
                            'descripcion': descripcion,
                            'exito': False,
                            'error': 'Comando bloqueado por seguridad'
                        })
                        continue
                    
                    # Ejecutar con lista de argumentos (más seguro que string)
                    resultado = subprocess.run(
                        comando_lista, 
                        capture_output=True, 
                        text=True, 
                        timeout=60,
                        check=False
                    )
                    
                    resultados.append({
                        'comando': comando_str,
                        'descripcion': descripcion,
                        'exito': resultado.returncode == 0,
                        'salida': resultado.stdout[:500] if resultado.stdout else '',
                        'codigo_retorno': resultado.returncode
                    })
                    
                except subprocess.TimeoutExpired:
                    resultados.append({
                        'comando': comando_str,
                        'descripcion': descripcion,
                        'exito': False,
                        'error': 'Timeout ejecutando comando'
                    })
                except Exception as e:
                    logging.error(f"Error ejecutando {comando_str}: {str(e)}")
                    resultados.append({
                        'comando': comando_str,
                        'descripcion': descripcion,
                        'exito': False,
                        'error': 'Error de ejecución'
                    })
            
            return {'exito': True, 'resultados': resultados}
        except Exception as e:
            logging.error(f"Error en limpieza del sistema: {str(e)}")
            return {'exito': False, 'error': 'Error general en limpieza'}
    
    def generar_reporte_completo(self, incluir_escaneo=None, incluir_monitoreo=None):
        datos_utilidades = {
            'herramientas': self.verificar_herramientas_disponibles(),
            'servicios': self.analizar_servicios_activos(),
            'permisos_archivos': self.verificar_permisos_criticos(),
            'hardware': self.obtener_informacion_hardware()
        }
        
        datos_escaneo = incluir_escaneo or {}
        datos_monitoreo = incluir_monitoreo or {}
        
        return self.reportes.generar_reporte_completo(
            datos_escaneo, datos_monitoreo, datos_utilidades
        )
    
    def guardar_reporte_json(self, reporte, nombre_archivo=None):
        return self.reportes.guardar_reporte_json(reporte, nombre_archivo)
    
    def guardar_reporte_texto(self, reporte, nombre_archivo=None):
        return self.reportes.guardar_reporte_texto(reporte, nombre_archivo)
    
    def listar_reportes_guardados(self):
        return self.reportes.listar_reportes()
    
    def obtener_reporte_texto(self, reporte):
        return self.reportes.generar_reporte_texto(reporte)
    
    def listar_wordlists(self):
        return self.gestor_wordlists.listar_wordlists()
    
    def cargar_wordlist(self, ruta_origen, nombre_destino=None):
        """Carga wordlist con validación de nombre"""
        if nombre_destino and not self._validar_nombre_archivo(nombre_destino):
            logging.warning(f"Nombre de wordlist inseguro: {nombre_destino}")
            return {'exito': False, 'error': 'Nombre no válido'}
        return self.gestor_wordlists.cargar_wordlist(ruta_origen, nombre_destino)
    
    def obtener_contenido_wordlist(self, nombre):
        """Obtiene contenido con validación de nombre"""
        if not self._validar_nombre_archivo(nombre):
            logging.warning(f"Nombre de wordlist inseguro: {nombre}")
            return {'exito': False, 'error': 'Nombre no válido'}
        return self.gestor_wordlists.obtener_contenido_wordlist(nombre)
    
    def guardar_wordlist(self, nombre, contenido):
        """Guarda wordlist con validación de nombre"""
        if not self._validar_nombre_archivo(nombre):
            logging.warning(f"Nombre de wordlist inseguro: {nombre}")
            return {'exito': False, 'error': 'Nombre no válido'}
        return self.gestor_wordlists.guardar_wordlist(nombre, contenido)
    
    def eliminar_wordlist(self, nombre):
        """Elimina wordlist con validación de nombre"""
        if not self._validar_nombre_archivo(nombre):
            logging.warning(f"Nombre de wordlist inseguro: {nombre}")
            return {'exito': False, 'error': 'Nombre no válido'}
        return self.gestor_wordlists.eliminar_wordlist(nombre)
    
    def exportar_wordlist(self, nombre, ruta_destino):
        return self.gestor_wordlists.exportar_wordlist(nombre, ruta_destino)
    
    def buscar_en_wordlist(self, nombre, termino):
        return self.gestor_wordlists.buscar_en_wordlist(nombre, termino)
    
    def listar_diccionarios(self):
        return self.gestor_diccionarios.listar_diccionarios()
    
    def cargar_diccionario(self, ruta_origen, nombre_destino=None):
        return self.gestor_diccionarios.cargar_diccionario(ruta_origen, nombre_destino)
    
    def obtener_contenido_diccionario(self, nombre):
        return self.gestor_diccionarios.obtener_contenido_diccionario(nombre)
    
    def guardar_diccionario(self, nombre, contenido):
        return self.gestor_diccionarios.guardar_diccionario(nombre, contenido)
    
    def eliminar_diccionario(self, nombre):
        return self.gestor_diccionarios.eliminar_diccionario(nombre)
    
    def exportar_diccionario_txt(self, nombre, ruta_destino):
        return self.gestor_diccionarios.exportar_diccionario_txt(nombre, ruta_destino)
    
    def buscar_en_diccionario(self, nombre, termino):
        return self.gestor_diccionarios.buscar_en_diccionario(nombre, termino)
    
    def agregar_entrada_diccionario(self, nombre, clave, valor):
        return self.gestor_diccionarios.agregar_entrada(nombre, clave, valor)
    
    def eliminar_entrada_diccionario(self, nombre, clave):
        return self.gestor_diccionarios.eliminar_entrada(nombre, clave)
    
    def cargar_wordlist_desde_archivo(self, archivo, nombre):
        return self.gestor_wordlists.cargar_wordlist(archivo, nombre)
    
    def crear_wordlist_vacia(self, nombre):
        return self.gestor_wordlists.guardar_wordlist(nombre, "")
    
    def cargar_diccionario_desde_archivo(self, archivo, nombre):
        return self.gestor_diccionarios.cargar_diccionario(archivo, nombre)
    
    def obtener_diccionario_completo(self, nombre):
        resultado = self.gestor_diccionarios.obtener_contenido_diccionario(nombre)
        if resultado.get('exito', False):
            return resultado.get('contenido', {})
        return None
    
    def guardar_diccionario_completo(self, nombre, contenido):
        resultado = self.gestor_diccionarios.guardar_diccionario(nombre, contenido)
        return resultado.get('exito', False)

# RESUMEN TÉCNICO: Controlador central para utilidades del sistema Kali Linux, gestión de wordlists 
# de pentesting, diccionarios de ciberseguridad y generación de reportes de auditoría. Implementa 
# patrón MVC con responsabilidad única siguiendo SOLID, integración nativa con herramientas de Kali 
# (nmap, lynis, chkrootkit), sin dependencias externas. Arquitectura modular DRY para profesionales 
# de ciberseguridad con interfaz oscura optimizada 1400x900.
