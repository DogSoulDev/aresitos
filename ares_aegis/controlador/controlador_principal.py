# -*- coding: utf-8 -*-

from ares_aegis.controlador.controlador_escaneo import ControladorEscaneo
from ares_aegis.controlador.controlador_monitoreo import ControladorMonitoreo
from ares_aegis.controlador.controlador_utilidades import ControladorUtilidades

class ControladorPrincipal:
    def __init__(self, modelo, vista):
        self.modelo = modelo
        self.vista = vista
        
        self.controlador_escaneo = ControladorEscaneo(modelo)
        self.controlador_monitoreo = ControladorMonitoreo(modelo)
        self.controlador_utilidades = ControladorUtilidades(modelo)


# RESUMEN: Controlador principal que coordina la lógica de negocio entre modelo y vista.