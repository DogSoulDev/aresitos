# -*- coding: utf-8 -*-

from ares_aegis.modelo.utilidades import Utilidades
from ares_aegis.modelo.reportes import Reportes
from ares_aegis.modelo.gestor_wordlists import GestorWordlists
from ares_aegis.modelo.gestor_diccionarios import GestorDiccionarios

class ControladorUtilidades:
    
    def __init__(self, modelo_principal):
        self.modelo_principal = modelo_principal
        self.utilidades = Utilidades()
        self.reportes = Reportes()
        self.gestor_wordlists = GestorWordlists()
        self.gestor_diccionarios = GestorDiccionarios()
    
    def verificar_herramientas_disponibles(self):
        return self.utilidades.verificar_herramientas_kali_completo()  # Método existente
    
    def ejecutar_auditoria_lynis(self):
        return self.utilidades.ejecutar_auditoria_completa_lynis()  # Método existente
    
    def ejecutar_deteccion_rootkit(self):
        return self.utilidades.ejecutar_deteccion_rootkits_completa()  # Método existente
    
    def analizar_servicios_activos(self):
        return self.utilidades.analizar_servicios_sistema_avanzado()  # Método existente
    
    def verificar_permisos_criticos(self):
        return self.utilidades.verificar_permisos_archivos_criticos_avanzado()  # Método existente
    
    def obtener_informacion_hardware(self):
        return self.utilidades.obtener_info_hardware_completa()  # Método existente
    
    def ejecutar_limpieza_sistema(self):
        # Crear función alternativa ya que no existe el método original
        return {"status": "warning", "mensaje": "Función de limpieza no implementada"}  
    
    def generar_reporte_completo(self, incluir_escaneo=None, incluir_monitoreo=None):
        datos_utilidades = {
            'herramientas': self.verificar_herramientas_disponibles(),
            'servicios': self.analizar_servicios_activos(),
            'permisos_archivos': self.verificar_permisos_criticos(),
            'hardware': self.obtener_informacion_hardware()
        }
        
        datos_escaneo = incluir_escaneo or {}
        
        datos_monitoreo = incluir_monitoreo or {}
        
        reporte = self.reportes.generar_reporte_completo(
            datos_escaneo, datos_monitoreo, datos_utilidades
        )
        
        return reporte
    
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
        return self.gestor_wordlists.cargar_wordlist(ruta_origen, nombre_destino)
    
    def obtener_contenido_wordlist(self, nombre):
        return self.gestor_wordlists.obtener_contenido_wordlist(nombre)
    
    def guardar_wordlist(self, nombre, contenido):
        return self.gestor_wordlists.guardar_wordlist(nombre, contenido)
    
    def eliminar_wordlist(self, nombre):
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
        return self.gestor_diccionarios.obtener_contenido_diccionario(nombre)
    
    def guardar_diccionario_completo(self, nombre, contenido):
        return self.gestor_diccionarios.guardar_diccionario(nombre, contenido)


# RESUMEN: Controlador para utilidades, wordlists, diccionarios y reportes.