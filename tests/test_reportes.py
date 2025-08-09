# -*- coding: utf-8 -*-

import unittest
import tempfile
import os
import json
from unittest.mock import patch
import sys

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from ares_aegis.modelo.reportes import Reportes

class TestReportes(unittest.TestCase):
    
    def setUp(self):
        self.reportes = Reportes()
        self.temp_dir = tempfile.mkdtemp()
        self.reportes.directorio_reportes = self.temp_dir
    
    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_generar_reporte_completo_basico(self):
        datos_escaneo = {'puertos': ['puerto 22 abierto'], 'analisis': ['Sistema OK']}
        datos_monitoreo = {'memoria': 75.5, 'procesos': 150}
        datos_utilidades = {'herramientas': {'disponibles': ['nmap'], 'no_disponibles': []}}
        
        reporte = self.reportes.generar_reporte_completo(
            datos_escaneo, datos_monitoreo, datos_utilidades
        )
        
        self.assertIsInstance(reporte, dict)
        self.assertIn('metadata', reporte)
        self.assertIn('resumen_ejecutivo', reporte)
        self.assertIn('escaneo_sistema', reporte)
        self.assertIn('monitoreo_sistema', reporte)
        self.assertIn('utilidades_sistema', reporte)
        self.assertIn('recomendaciones', reporte)
    
    def test_generar_resumen_ejecutivo(self):
        datos_escaneo = {'analisis': ['ERROR crítico', 'WARNING menor', 'Info normal']}
        datos_monitoreo = {}
        
        resumen = self.reportes._generar_resumen_ejecutivo(datos_escaneo, datos_monitoreo)
        
        self.assertIsInstance(resumen, dict)
        self.assertIn('estado_general', resumen)
        self.assertIn('alertas_criticas', resumen)
        self.assertIn('alertas_medias', resumen)
        self.assertIn('puntuacion_seguridad', resumen)
        
        self.assertEqual(resumen['alertas_criticas'], 1)
        self.assertEqual(resumen['alertas_medias'], 1)
    
    def test_generar_recomendaciones(self):
        datos_escaneo = {}
        datos_utilidades = {
            'herramientas': {'no_disponibles': ['lynis', 'chkrootkit']},
            'permisos_archivos': [
                {'archivo': '/etc/shadow', 'permisos': '644'},  # Permisos incorrectos
                {'archivo': '/etc/passwd', 'permisos': '644'}
            ]
        }
        
        recomendaciones = self.reportes._generar_recomendaciones(datos_escaneo, datos_utilidades)
        
        self.assertIsInstance(recomendaciones, list)
        self.assertTrue(len(recomendaciones) > 0)
        
        herramientas_recomendadas = [r for r in recomendaciones if r['categoria'] == 'HERRAMIENTAS']
        self.assertTrue(len(herramientas_recomendadas) > 0)
    
    def test_guardar_reporte_json_exito(self):
        reporte = {
            'metadata': {'version': '1.0'},
            'datos': {'test': 'valor'}
        }
        
        resultado = self.reportes.guardar_reporte_json(reporte, "test_reporte.json")
        
        self.assertTrue(resultado['exito'])
        self.assertIn('archivo', resultado)
        self.assertIn('tamaño', resultado)
        
        ruta_archivo = resultado['archivo']
        self.assertTrue(os.path.exists(ruta_archivo))
        
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            contenido = json.load(f)
            self.assertEqual(contenido['metadata']['version'], '1.0')
    
    def test_guardar_reporte_json_sin_directorio(self):
        self.reportes.directorio_reportes = None
        
        resultado = self.reportes.guardar_reporte_json({'test': 'data'})
        
        self.assertFalse(resultado['exito'])
        self.assertIn('no disponible', resultado['error'])
    
    def test_generar_reporte_texto(self):
        reporte = {
            'metadata': {
                'generado_en': '2025-08-09T12:00:00',
                'sistema': {'system': 'Linux', 'release': '5.4.0'}
            },
            'resumen_ejecutivo': {
                'estado_general': 'BUENO',
                'puntuacion_seguridad': 85,
                'alertas_criticas': 0,
                'alertas_medias': 2
            },
            'recomendaciones': [
                {'prioridad': 'ALTA', 'descripcion': 'Actualizar sistema', 'comando': 'apt update'},
                {'prioridad': 'MEDIA', 'descripcion': 'Revisar logs', 'comando': 'tail /var/log/syslog'}
            ]
        }
        
        texto = self.reportes.generar_reporte_texto(reporte)
        
        self.assertIsInstance(texto, str)
        self.assertIn('REPORTE DE SEGURIDAD ARESITOS', texto)
        self.assertIn('RESUMEN EJECUTIVO', texto)
        self.assertIn('BUENO', texto)
        self.assertIn('85/100', texto)
        self.assertIn('RECOMENDACIONES PRIORITARIAS', texto)
    
    def test_guardar_reporte_texto_exito(self):
        reporte = {
            'metadata': {'generado_en': '2025-08-09T12:00:00'},
            'resumen_ejecutivo': {'estado_general': 'BUENO'}
        }
        
        resultado = self.reportes.guardar_reporte_texto(reporte, "test_reporte.txt")
        
        self.assertTrue(resultado['exito'])
        self.assertIn('archivo', resultado)
        
        ruta_archivo = resultado['archivo']
        self.assertTrue(os.path.exists(ruta_archivo))
        
        with open(ruta_archivo, 'r', encoding='utf-8') as f:
            contenido = f.read()
            self.assertIn('REPORTE DE SEGURIDAD ARESITOS', contenido)
    
    def test_listar_reportes_directorio_vacio(self):
        reportes = self.reportes.listar_reportes()
        
        self.assertIsInstance(reportes, list)
        self.assertEqual(len(reportes), 0)
    
    def test_listar_reportes_con_archivos(self):
        nombre_archivo = "reporte_aresitos_20250809_120000.json"
        ruta_archivo = os.path.join(self.temp_dir, nombre_archivo)
        with open(ruta_archivo, 'w') as f:
            json.dump({'test': 'data'}, f)
        
        reportes = self.reportes.listar_reportes()
        
        self.assertIsInstance(reportes, list)
        self.assertEqual(len(reportes), 1)
        
        reporte = reportes[0]
        self.assertEqual(reporte['nombre'], nombre_archivo)
        self.assertIn('ruta', reporte)
        self.assertIn('tamaño', reporte)
        self.assertIn('modificado', reporte)

if __name__ == '__main__':
    unittest.main()


# RESUMEN: Generador de reportes de seguridad en múltiples formatos.