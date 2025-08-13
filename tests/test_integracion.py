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
        """Test que el controlador principal se inicializa correctamente"""
        self.assertIsNotNone(self.controlador.modelo)
        self.assertIsNotNone(self.controlador._controladores)
        self.assertIn('escaneo', self.controlador._controladores)
        self.assertIn('monitoreo', self.controlador._controladores)
        self.assertIn('utilidades', self.controlador._controladores)
    
    def test_controladores_especificos_disponibles(self):
        """Test que los controladores específicos tienen métodos esperados"""
        escaneo = self.controlador._controladores.get('escaneo')
        monitoreo = self.controlador._controladores.get('monitoreo')
        utilidades = self.controlador._controladores.get('utilidades')
        
        if escaneo:
            self.assertTrue(hasattr(escaneo, 'ejecutar_escaneo_basico'))
        if monitoreo:
            self.assertTrue(hasattr(monitoreo, 'iniciar_monitoreo'))
        if utilidades:
            self.assertTrue(hasattr(utilidades, 'verificar_herramientas_disponibles'))
    
    def test_funcionalidad_escaneador_avanzado(self):
        """Test de funcionalidad del escaneador avanzado"""
        try:
            from ares_aegis.modelo.modelo_escaneador import EscaneadorAvanzado, TipoEscaneo
            
            escaneador = EscaneadorAvanzado()
            resultado = escaneador.escanear_avanzado('127.0.0.1', TipoEscaneo.PUERTOS_BASICO)
            
            self.assertIsNotNone(resultado)
            self.assertEqual(resultado.objetivo, '127.0.0.1')
            self.assertEqual(resultado.tipo_escaneo, TipoEscaneo.PUERTOS_BASICO)
            
        except Exception as e:
            # Permitir errores de herramientas no disponibles
            self.assertIsInstance(e, (OSError, FileNotFoundError, PermissionError))
    
    def test_funcionalidad_siem_avanzado(self):
        """Test de funcionalidad del SIEM avanzado"""
        try:
            from ares_aegis.modelo.modelo_siem import SIEMAvanzado, TipoEvento, SeveridadEvento
            
            siem = SIEMAvanzado()
            
            # Registrar evento de prueba con enums correctos
            siem.registrar_evento(TipoEvento.AUDITORIA, 'Test de integración', {'test': True}, SeveridadEvento.INFO)
            
            # Verificar que el evento se registró
            self.assertGreater(siem.metricas['eventos_procesados'], 0)
            
        except Exception as e:
            self.fail(f"Error en SIEM: {e}")
    
    def test_funcionalidad_monitor_avanzado(self):
        """Test de funcionalidad del monitor avanzado"""
        try:
            from ares_aegis.modelo.modelo_monitor import MonitorAvanzado
            
            monitor = MonitorAvanzado()
            
            # Verificar que el monitor se inicializa correctamente
            self.assertIsNotNone(monitor)
            self.assertTrue(hasattr(monitor, 'obtener_procesos_sospechosos'))
            
        except Exception as e:
            self.fail(f"Error en monitor: {e}")
    
    def test_metodos_avanzados_controlador_principal(self):
        """Test de métodos avanzados en el controlador principal"""
        try:
            # Test método de escaneo avanzado si está disponible
            if hasattr(self.controlador, 'ejecutar_escaneo_avanzado'):
                from ares_aegis.modelo.modelo_escaneador import TipoEscaneo
                resultado = self.controlador.ejecutar_escaneo_avanzado('127.0.0.1', TipoEscaneo.PUERTOS_BASICO.value)
                self.assertIsNotNone(resultado)
            
            # Test método de procesos sospechosos si está disponible
            if hasattr(self.controlador, 'obtener_procesos_sospechosos'):
                procesos = self.controlador.obtener_procesos_sospechosos()
                self.assertIsInstance(procesos, list)
            
            # Test método de alertas de seguridad si está disponible
            if hasattr(self.controlador, 'obtener_alertas_seguridad'):
                alertas = self.controlador.obtener_alertas_seguridad()
                self.assertIsInstance(alertas, list)
                
        except Exception as e:
            # Permitir errores de herramientas no disponibles
            self.assertIsInstance(e, (OSError, FileNotFoundError, PermissionError, ImportError))
    
    def test_compatibility_layer(self):
        """Test de la capa de compatibilidad"""
        try:
            from ares_aegis.modelo.modelo_escaneador import Escaneador
            
            escaneador = Escaneador()
            self.assertIsNotNone(escaneador)
            self.assertTrue(hasattr(escaneador, 'es_kali'))
            
        except Exception as e:
            self.fail(f"Error en capa de compatibilidad: {e}")

if __name__ == '__main__':
    unittest.main()


# RESUMEN: Tests de integración para el sistema Ares Aegis mejorado con funcionalidad avanzada.
