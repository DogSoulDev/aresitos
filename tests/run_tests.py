# -*- coding: utf-8 -*-


import unittest
import sys
import os

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

def run_all_tests():
    loader = unittest.TestLoader()
    suite = loader.discover('tests', pattern='test_*.py')
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

def run_specific_test_module(module_name):
    loader = unittest.TestLoader()
    suite = loader.loadTestsFromName(f'tests.{module_name}')
    
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    
    return result.wasSuccessful()

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Ejecutar tests de Aresitos')
    parser.add_argument('--module', '-m', help='Ejecutar tests de un módulo específico')
    parser.add_argument('--list', '-l', action='store_true', help='Listar módulos de test disponibles')
    
    args = parser.parse_args()
    
    if args.list:
        print("Módulos de test disponibles:")
        test_files = [f for f in os.listdir('tests') if f.startswith('test_') and f.endswith('.py')]
        for test_file in test_files:
            module_name = test_file[:-3]  # Remover .py
            print(f"  - {module_name}")
    elif args.module:
        print(f"Ejecutando tests del módulo: {args.module}")
        success = run_specific_test_module(args.module)
        sys.exit(0 if success else 1)
    else:
        print("Ejecutando todos los tests...")
        success = run_all_tests()
        sys.exit(0 if success else 1)


# RESUMEN: Módulo de pruebas unitarias.