# -*- coding: utf-8 -*-

from ares_aegis.modelo.monitor import Monitor
from ares_aegis.modelo.cuarentena import Cuarentena

class ControladorMonitoreo:
    
    def __init__(self, modelo_principal):
        self.modelo_principal = modelo_principal
        self.monitor = Monitor()
        self.cuarentena = Cuarentena()
    
    def iniciar_monitoreo(self):
        return self.monitor.iniciar_monitoreo_completo()  # Método existente
    
    def detener_monitoreo(self):
        self.monitor.detener_monitoreo()
    
    def obtener_estado_monitoreo(self):
        return {
            "activo": self.monitor.monitoreando,
            "datos_recientes": self.monitor.obtener_datos_sistema_recientes(10)  # Método existente
        }
    
    def obtener_metricas_sistema(self):
        return self.monitor.obtener_datos_sistema_recientes(1)  # Método existente
    
    def monitorear_red(self):
        return self.monitor.obtener_datos_red_recientes(10)  # Método existente
    
    def poner_archivo_en_cuarentena(self, ruta_archivo, motivo="Archivo detectado como sospechoso"):
        return self.cuarentena.poner_en_cuarentena(ruta_archivo, motivo)
    
    def restaurar_archivo_cuarentena(self, hash_archivo):
        return self.cuarentena.restaurar_de_cuarentena(hash_archivo)
    
    def eliminar_archivo_cuarentena(self, hash_archivo):
        return self.cuarentena.eliminar_de_cuarentena(hash_archivo)
    
    def listar_archivos_cuarentena(self):
        return self.cuarentena.listar_cuarentena()
    
    def limpiar_cuarentena_completa(self):
        # Usar método existente que elimina todos los archivos
        items = self.cuarentena.listar_cuarentena()
        resultados = []
        for item in items:
            if 'id' in item:
                resultado = self.cuarentena.eliminar_de_cuarentena(item['id'])
                resultados.append(resultado)
        return {'eliminados': len(resultados), 'detalles': resultados}


# RESUMEN: Sistema de monitoreo de red y procesos usando herramientas nativas.