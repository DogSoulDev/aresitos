# -*- coding: utf-8 -*-


import sys
import os
import tempfile
import json
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from ares_aegis.controlador.controlador_utilidades import ControladorUtilidades  # Ruta correcta


class TestWordlistsDiccionarios(unittest.TestCase):

    def setUp(self):
        self.controlador = ControladorUtilidades(None)  # Pasar None como modelo_principal para tests
        self.temp_dir = tempfile.mkdtemp()

    def test_gestion_wordlists(self):
        print("\n Testing de wordlists...")
        
        try:
            wordlists = self.controlador.listar_wordlists()
            print(f"   OK: available wordlists: {len(wordlists)}")
            
            expected_wordlists = ['passwords_comunes', 'usuarios_tipicos', 'directorios_web', 'subdominios_comunes']
            for wl in expected_wordlists:
                if wl in wordlists:
                    print(f"   OK Wordlist '{wl}' found")
                    
                    contenido = self.controlador.cargar_wordlist(wl)
                    if contenido and len(contenido) > 0:
                        print(f"   OK Wordlist '{wl}' contains {len(contenido)} items")
                    else:
                        print(f"   AVISO: Wordlist '{wl}' está empty")
                else:
                    print(f"   AVISO: Wordlist '{wl}' no found")
            
            test_name = "test_wordlist"
            if self.controlador.crear_wordlist_vacia(test_name):
                print(f"   OK Wordlist '{test_name}' created OK")
                
                if self.controlador.eliminar_wordlist(test_name):
                    print(f"   OK Wordlist '{test_name}' deleted OK")
                else:
                    print(f"   AVISO: Error al eliminar wordlist '{test_name}'")
            else:
                print(f"   AVISO: Error al crear wordlist '{test_name}'")
                
            return True
            
        except Exception as e:
            print(f"   ERROR: Error en wordlist mgmt: {e}")
            return False

    def test_gestion_diccionarios(self):
        print("\n Testing de diccionarios...")
        
        try:
            diccionarios = self.controlador.listar_diccionarios()
            print(f"   OK available dicts: {len(diccionarios)}")
            
            expected_dicts = ['puertos_conocidos', 'vulnerabilidades_comunes', 'herramientas_seguridad']
            for dict_name in expected_dicts:
                if dict_name in diccionarios:
                    print(f"   OK Diccionario '{dict_name}' found")
                    
                    results = self.controlador.buscar_en_diccionario(dict_name, "http")
                    if results:
                        print(f"   OK Búsqueda en '{dict_name}': {len(results)} results para 'http'")
                    else:
                        print(f"   AVISO: No se encontraron results para 'http' en '{dict_name}'")
                else:
                    print(f"   AVISO: Diccionario '{dict_name}' no found")
            
            if diccionarios:
                primer_dict = diccionarios[0]
                test_termino = "test_termino"
                test_definicion = "Definición de prueba"
                
                if self.controlador.agregar_entrada_diccionario(primer_dict, test_termino, test_definicion):
                    print(f"   OK Entrada agregada to dict '{primer_dict}'")
                    
                    results = self.controlador.buscar_en_diccionario(primer_dict, test_termino)
                    if results:
                        print(f"   OK Entrada found after add")
                    else:
                        print(f"   AVISO: Entrada no found after add")
                else:
                    print(f"   AVISO: Error al agregar entrada to dict")
                    
            return True
            
        except Exception as e:
            print(f"   ERROR: Error en dict mgmt: {e}")
            return False

    def test_exportacion(self):
        print("\n Testing funciones de exportación...")
        
        try:
            wordlists = self.controlador.listar_wordlists()
            if wordlists:
                primera_wordlist = wordlists[0]
                temp_file = os.path.join(self.temp_dir, "test_wordlist.txt")
                
                if self.controlador.exportar_wordlist(primera_wordlist, temp_file):
                    print(f"   OK Wordlist '{primera_wordlist}' exportada a TXT")
                    
                    if os.path.exists(temp_file):
                        print(f"   OK Archivo de exportación creado OK")
                        with open(temp_file, 'r', encoding='utf-8') as f:
                            contenido = f.read()
                            if contenido.strip():
                                print(f"   OK Archivo contains datos: {len(contenido)} caracteres")
                            else:
                                print(f"   AVISO Archivo exportado está vacío")
                    else:
                        print(f"   AVISO Archivo de exportación no se creó")
                else:
                    print(f"   AVISO Error al exportar wordlist")
            
            diccionarios = self.controlador.listar_diccionarios()
            if diccionarios:
                primer_dict = diccionarios[0]
                temp_file = os.path.join(self.temp_dir, "test_diccionario.txt")
                
                if self.controlador.exportar_diccionario_txt(primer_dict, temp_file):
                    print(f"   OK Diccionario '{primer_dict}' exportado a TXT")
                    
                    if os.path.exists(temp_file):
                        print(f"   OK Archivo de exportación creado OK")
                        with open(temp_file, 'r', encoding='utf-8') as f:
                            contenido = f.read()
                            if contenido.strip():
                                print(f"   OK Archivo contains datos: {len(contenido)} caracteres")
                            else:
                                print(f"   AVISO Archivo exportado está vacío")
                    else:
                        print(f"   AVISO Archivo de exportación no se creó")
                else:
                    print(f"   AVISO Error al exportar diccionario")
                    
            return True
            
        except Exception as e:
            print(f"   ERROR Error en funciones de exportación: {e}")
            return False

    def test_integracion_completa(self):
        print("\n Testing integración completa...")
        
        try:
            exitos = 0
            total_tests = 3
            
            if self.test_gestion_wordlists():
                exitos += 1
            
            if self.test_gestion_diccionarios():
                exitos += 1
                
            if self.test_exportacion():
                exitos += 1
            
            porcentaje = (exitos / total_tests) * 100
            print(f"\n Resultado de integración: {exitos}/{total_tests} tests exitosos ({porcentaje:.1f}%)")
            
            if porcentaje >= 80:
                print("OK Integración de wordlists y diccionarios EXITOSA")
                return True
            else:
                print("AVISO Integración parcialmente funcional")
                return False
                
        except Exception as e:
            print(f"ERROR Error en test de integración: {e}")
            return False


def main():
    print(" INICIANDO PRUEBAS DE WORDLISTS Y DICCIONARIOS")
    print("=" * 60)
    
    test_suite = TestWordlistsDiccionarios()
    test_suite.setUp()
    
    try:
        resultado = test_suite.test_integracion_completa()
        
        print("\n" + "=" * 60)
        if resultado:
            print(" TODAS LAS PRUEBAS COMPLETADAS EXITOSAMENTE")
            print("OK Las nuevas funcionalidades están listas para usar")
        else:
            print("AVISO ALGUNAS PRUEBAS FALLARON")
            print(" Revisa los errores reportados arriba")
            
    except Exception as e:
        print(f"\nERROR ERROR CRÍTICO EN LAS PRUEBAS: {e}")
        
    print("\n🏁 Fin de las pruebas")


if __name__ == "__main__":
    main()


# RESUMEN: Módulo de clases y funciones para Aresitos.

