# -*- coding: utf-8 -*-

import unittest
import platform
from unittest.mock import patch, MagicMock
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ares_aegis.modelo.escaneador import Escaneador

class TestEscaneador(unittest.TestCase):
    
    def setUp(self):
        self.escaneador = Escaneador()
    
    def test_detectar_kali(self):
        if platform.system() == "Windows":
            self.assertFalse(self.escaneador.es_kali)
    
    @patch('subprocess.run')
    def test_escanear_puertos_ss_exito(self, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "Proto Local Address State\ntcp 127.0.0.1:22 LISTEN"
        mock_run.return_value = mock_result
        
        self.escaneador.es_kali = True
        
        resultado = self.escaneador.escanear_puertos_ss()  # Método correcto
        
        self.assertIsInstance(resultado, dict)
        self.assertTrue('exito' in resultado)
        mock_run.assert_called_once()
    
    @patch('subprocess.run')
    def test_escanear_puertos_error(self, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_run.return_value = mock_result
        
        self.escaneador.es_kali = True
        
        resultado = self.escaneador.escanear_puertos_ss()  # Método correcto
        
        self.assertIsInstance(resultado, dict)
        self.assertFalse(resultado.get('exito', True))
    
    @patch('subprocess.run')
    def test_escanear_procesos_avanzado_exito(self, mock_run):
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = "USER PID %CPU %MEM VSZ RSS TTY STAT START TIME COMMAND\nroot 1 0.0 0.1 225484 9876 ? Ss 10:00 0:01 /sbin/init"
        mock_run.return_value = mock_result
        
        resultado = self.escaneador.escanear_procesos_avanzado()  # Método correcto
        
        self.assertIsInstance(resultado, dict)
        self.assertTrue('exito' in resultado)
        mock_run.assert_called_once()
    
    def test_escanear_puertos_no_kali(self):
        self.escaneador.es_kali = False
        
        resultado = self.escaneador.escanear_puertos_ss()  # Método correcto
        
        self.assertIsInstance(resultado, dict)
        self.assertFalse(resultado.get('exito', True))

if __name__ == '__main__':
    unittest.main()


# RESUMEN: Módulo de escaneo que detecta Kali Linux y ejecuta comandos nativos.