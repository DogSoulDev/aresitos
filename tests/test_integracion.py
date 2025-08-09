# -*- coding: utf-8 -*-

import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ares_aegis.controlador.controlador_principal import ControladorPrincipal
from ares_aegis.modelo.modelo_principal import ModeloPrincipal

class TestIntegracionMVC(unittest.TestCase):
    
    def setUp(self):
        self.modelo = ModeloPrincipal()
        self.vista_mock = None
        self.controlador = ControladorPrincipal(self.modelo, self.vista_mock)
    
    def test_inicializacion_controlador_principal(self):
        self.assertIsNotNone(self.controlador.modelo)
        self.assertIsNotNone(self.controlador.controlador_escaneo)
        self.assertIsNotNone(self.controlador.controlador_monitoreo)
        self.assertIsNotNone(self.controlador.controlador_utilidades)
    
    def test_controladores_especificos_disponibles(self):
        self.assertTrue(hasattr(self.controlador.controlador_escaneo, 'ejecutar_escaneo_basico'))
        self.assertTrue(hasattr(self.controlador.controlador_monitoreo, 'iniciar_monitoreo'))
        self.assertTrue(hasattr(self.controlador.controlador_utilidades, 'verificar_herramientas_disponibles'))
    
    def test_flujo_escaneo_completo(self):
        try:
            resultado = self.controlador.controlador_escaneo.ejecutar_escaneo_basico()
            
            self.assertIsInstance(resultado, dict)
            self.assertIn('puertos', resultado)
            self.assertIn('procesos', resultado)
            self.assertIn('analisis', resultado)
            
            eventos = self.controlador.controlador_escaneo.obtener_eventos_siem(5)
            self.assertIsInstance(eventos, list)
            
        except Exception as e:
            self.assertIsInstance(e, (OSError, FileNotFoundError, PermissionError))
    
    def test_flujo_monitoreo_completo(self):
        try:
            exito = self.controlador.controlador_monitoreo.iniciar_monitoreo()
            self.assertIsInstance(exito, bool)
            
            if exito:
                estado = self.controlador.controlador_monitoreo.obtener_estado_monitoreo()
                self.assertIsInstance(estado, dict)
                self.assertIn('activo', estado)
                
                self.controlador.controlador_monitoreo.detener_monitoreo()
                
        except Exception as e:
            self.assertIsInstance(e, (OSError, FileNotFoundError, PermissionError))
    
    def test_flujo_utilidades_completo(self):
        try:
            herramientas = self.controlador.controlador_utilidades.verificar_herramientas_disponibles()
            self.assertIsInstance(herramientas, dict)
            self.assertIn('disponibles', herramientas)
            self.assertIn('no_disponibles', herramientas)
            
            hardware = self.controlador.controlador_utilidades.obtener_informacion_hardware()
            self.assertIsInstance(hardware, dict)
            
        except Exception as e:
            self.assertIsInstance(e, (OSError, FileNotFoundError, PermissionError))
    
    def test_flujo_reportes_completo(self):
        try:
            reporte = self.controlador.controlador_utilidades.generar_reporte_completo()
            
            self.assertIsInstance(reporte, dict)
            self.assertIn('metadata', reporte)
            self.assertIn('resumen_ejecutivo', reporte)
            
            texto = self.controlador.controlador_utilidades.obtener_reporte_texto(reporte)
            self.assertIsInstance(texto, str)
            self.assertIn('REPORTE DE SEGURIDAD', texto)
            
        except Exception as e:
            self.assertIsInstance(e, (OSError, FileNotFoundError, PermissionError))

class TestCompatibilidadSistema(unittest.TestCase):
    
    def test_deteccion_sistema_operativo(self):
        import platform
        sistema = platform.system()
        
        self.assertIn(sistema, ['Windows', 'Linux', 'Darwin'])
    
    def test_importacion_modulos(self):
        try:
            from ares_aegis.modelo.escaneador import Escaneador
            from ares_aegis.modelo.monitor import Monitor
            from ares_aegis.modelo.cuarentena import Cuarentena
            from ares_aegis.modelo.utilidades import Utilidades
            from ares_aegis.modelo.reportes import Reportes
            from ares_aegis.modelo.siem import SIEM
            
            escaneador = Escaneador()
            monitor = Monitor()
            cuarentena = Cuarentena()
            utilidades = Utilidades()
            reportes = Reportes()
            siem = SIEM()
            
            self.assertIsNotNone(escaneador)
            self.assertIsNotNone(monitor)
            self.assertIsNotNone(cuarentena)
            self.assertIsNotNone(utilidades)
            self.assertIsNotNone(reportes)
            self.assertIsNotNone(siem)
            
        except ImportError as e:
            self.fail(f"Error importando módulos: {e}")

if __name__ == '__main__':
    unittest.main()


# RESUMEN: Módulo de clases y funciones para Aresitos.