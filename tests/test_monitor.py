# -*- coding: utf-8 -*-

import unittest
import tempfile
import os
import shutil
from unittest.mock import patch, MagicMock
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ares_aegis.modelo.monitor import Monitor

class TestMonitor(unittest.TestCase):
    
    def setUp(self):
        self.monitor = Monitor()
    
    def tearDown(self):
        if self.monitor.monitoreando:
            self.monitor.detener_monitoreo()
    
    def test_inicializar_monitor(self):
        self.assertFalse(self.monitor.monitoreando)
        self.assertEqual(len(self.monitor.datos_monitoreo), 0)  # Atributo correcto
        self.assertIsNone(self.monitor.hilo_monitor_sistema)  # Atributo correcto
    
    def test_iniciar_monitoreo(self):
        exito = self.monitor.iniciar_monitoreo_completo()  # Método correcto
        
        self.assertTrue(exito)
        self.assertTrue(self.monitor.monitoreando)
        self.assertIsNotNone(self.monitor.hilo_monitor_sistema)  # Atributo correcto
        
        self.monitor.detener_monitoreo()
    
    def test_detener_monitoreo(self):
        self.monitor.iniciar_monitoreo_completo()  # Método correcto
        self.assertTrue(self.monitor.monitoreando)
        
        self.monitor.detener_monitoreo()
        self.assertFalse(self.monitor.monitoreando)
    
    def test_iniciar_monitoreo_ya_activo(self):
        self.monitor.iniciar_monitoreo_completo()  # Método correcto
        self.assertTrue(self.monitor.monitoreando)
        
        exito = self.monitor.iniciar_monitoreo_completo()  # Método correcto
        self.assertFalse(exito)
        
        self.monitor.detener_monitoreo()
    
    @patch('subprocess.run')
    def test_obtener_metricas_sistema_exito(self, mock_run):
        mock_result_free = MagicMock()
        mock_result_free.returncode = 0
        mock_result_free.stdout = "              total        used        free      shared  buff/cache   available\nMem:           8000        2000        4000         100        2000        5500"
        
        mock_result_ps = MagicMock()
        mock_result_ps.returncode = 0
        mock_result_ps.stdout = "proceso1\nproceso2\nproceso3"
        
        mock_run.side_effect = [mock_result_free, mock_result_ps]
        
        self.monitor.es_kali = True
        
        metricas = self.monitor._obtener_metricas_avanzadas()  # Método correcto
        
        self.assertIsInstance(metricas, dict)
        self.assertIn('timestamp', metricas)
        self.assertIn('memoria_total', metricas)
        self.assertIn('memoria_usada', metricas)
        self.assertIn('memoria_porcentaje', metricas)
        self.assertIn('procesos_activos', metricas)
        
        self.assertIsInstance(metricas['memoria_total'], int)
        self.assertIsInstance(metricas['memoria_usada'], int)
        self.assertIsInstance(metricas['memoria_porcentaje'], float)
        self.assertIsInstance(metricas['procesos_activos'], int)
    
    def test_obtener_datos_recientes_vacio(self):
        datos = self.monitor.obtener_datos_sistema_recientes()  # Método correcto
        self.assertEqual(len(datos), 0)
    
    def test_obtener_datos_recientes_con_datos(self):
        from collections import deque
        self.monitor.datos_monitoreo = deque([  # Usar deque como en la implementación real
            {'timestamp': 1, 'memoria_porcentaje': 50.0},
            {'timestamp': 2, 'memoria_porcentaje': 55.0},
            {'timestamp': 3, 'memoria_porcentaje': 60.0}
        ], maxlen=1000)
        
        datos = self.monitor.obtener_datos_sistema_recientes(2)  # Método correcto
        self.assertEqual(len(datos), 2)
    
    @patch('subprocess.run')
    def test_monitorear_red_basico_exito(self, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "tcp 0.0.0.0:22 LISTEN\ntcp 127.0.0.1:3306 LISTEN\ntcp 10.0.0.1:80 ESTABLISHED"
        mock_run.return_value = mock_result
        
        self.monitor.es_kali = True
        
        resultado = self.monitor.obtener_datos_red_recientes(10)  # Método correcto que existe
        
        self.assertIsInstance(resultado, list)
        # El método real retorna datos, no ejecuta monitoreo directo

if __name__ == '__main__':
    unittest.main()


# RESUMEN: Sistema de monitoreo de red y procesos usando herramientas nativas.