# -*- coding: utf-8 -*-

from ares_aegis.modelo.escaneador import Escaneador
from ares_aegis.modelo.siem import SIEM

class ControladorEscaneo:
    
    def __init__(self, modelo_principal):
        self.modelo_principal = modelo_principal
        self.escaneador = Escaneador()
        self.siem = SIEM()
    
    def ejecutar_escaneo_basico(self):
        resultados = {
            'puertos': self.escaneador.escanear_puertos_ss(),  # Método existente
            'procesos': self.escaneador.escanear_procesos_avanzado(),  # Método existente
            'analisis': self.siem.analizar_logs_sistema_avanzado()  # Método existente
        }
        
        self.siem.registrar_evento("ESCANEO", "Escaneo básico completado")
        
        return resultados
    
    def obtener_logs(self):
        return self.siem.analizar_logs_sistema_avanzado()  # Método existente
    
    def obtener_eventos_siem(self, limite=20):
        return self.siem.obtener_alertas_activas(limite)  # Método existente


# RESUMEN: Módulo de clases y funciones para Aresitos.