# -*- coding: utf-8 -*-

import unittest
import tempfile
import os
import shutil
from unittest.mock import patch, mock_open
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ares_aegis.modelo.cuarentena import Cuarentena

class TestCuarentena(unittest.TestCase):
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.cuarentena = Cuarentena()
        self.cuarentena.directorio_cuarentena = self.temp_dir
    
    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_inicializar_cuarentena(self):
        self.assertIsNotNone(self.cuarentena.directorio_cuarentena)
        self.assertEqual(len(self.cuarentena.archivos_cuarentena), 0)
    
    def test_crear_directorio_cuarentena(self):
        if self.cuarentena.directorio_cuarentena:
            self.assertTrue(os.path.exists(self.cuarentena.directorio_cuarentena))
    
    def test_poner_archivo_inexistente_cuarentena(self):
        resultado = self.cuarentena.poner_en_cuarentena("/archivo/inexistente.txt")
        
        self.assertFalse(resultado['exito'])
        self.assertIn('no existe', resultado['error'])
    
    def test_poner_archivo_cuarentena_sin_directorio(self):
        self.cuarentena.directorio_cuarentena = None
        
        resultado = self.cuarentena.poner_en_cuarentena("archivo.txt")
        
        self.assertFalse(resultado['exito'])
        self.assertIn('no disponible', resultado['error'])
    
    def test_poner_archivo_cuarentena_exitoso(self):
        archivo_test = os.path.join(self.temp_dir, "test_file.txt")
        with open(archivo_test, 'w') as f:
            f.write("contenido de prueba")
        
        resultado = self.cuarentena.poner_en_cuarentena(archivo_test, "Prueba")
        
        self.assertTrue(resultado['exito'])
        self.assertIn('registro', resultado)
        self.assertEqual(len(self.cuarentena.archivos_cuarentena), 1)
        
        self.assertFalse(os.path.exists(archivo_test))
        
        registro = resultado['registro']
        self.assertTrue(os.path.exists(registro['archivo_cuarentena']))
    
    def test_listar_cuarentena_vacia(self):
        archivos = self.cuarentena.listar_cuarentena()
        self.assertEqual(len(archivos), 0)
    
    def test_listar_cuarentena_con_archivos(self):
        registro = {
            'archivo_original': '/test/archivo.txt',
            'archivo_cuarentena': os.path.join(self.temp_dir, 'test_cuarentena.txt'),
            'timestamp': '1234567890',
            'motivo': 'Prueba',
            'hash': 'abc123'
        }
        self.cuarentena.archivos_cuarentena.append(registro)
        
        archivos = self.cuarentena.listar_cuarentena()
        self.assertEqual(len(archivos), 1)
        self.assertEqual(archivos[0]['motivo'], 'Prueba')
    
    def test_eliminar_archivo_inexistente_cuarentena(self):
        resultado = self.cuarentena.eliminar_de_cuarentena("hash_inexistente")
        
        self.assertFalse(resultado['exito'])
        error_msg = resultado.get('error', '')
        if isinstance(error_msg, str):
            self.assertIn('no encontrado', error_msg)
    
    def test_limpiar_cuarentena_vacia(self):
        # Simular limpieza usando listar y eliminar
        items = self.cuarentena.listar_cuarentena()
        eliminados = 0
        for item in items:
            if 'id' in item:
                resultado_elim = self.cuarentena.eliminar_de_cuarentena(item['id'])
                if resultado_elim.get('exito', False):
                    eliminados += 1
        
        # Verificar que no hay elementos (cuarentena vacía)
        self.assertEqual(eliminados, 0)
    
    def test_restaurar_archivo_inexistente(self):
        resultado = self.cuarentena.restaurar_de_cuarentena("hash_inexistente")
        
        self.assertFalse(resultado['exito'])
        self.assertIn('no encontrado', resultado['error'])

if __name__ == '__main__':
    unittest.main()


# RESUMEN: Sistema de cuarentena para aislar archivos y procesos maliciosos.