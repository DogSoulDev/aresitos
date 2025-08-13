# -*- coding: utf-8 -*-
"""
Ares Aegis - Prueba de Controladores
Script de prueba para verificar la funcionalidad de los controladores mejorados
"""

import asyncio
import sys
import os

# Añadir el directorio del proyecto al path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ares_aegis.controladores.controlador_base import ControladorBase
from ares_aegis.controladores.gestor_configuracion import GestorConfiguracion
from ares_aegis.controlador.controlador_principal import ControladorPrincipal
from ares_aegis.controlador.controlador_escaneo import ControladorEscaneo

class ModeloMock:
    """Modelo mock para pruebas."""
    pass

class VistaMock:
    """Vista mock para pruebas."""
    pass

async def probar_controlador_base():
    """Probar funcionalidad del controlador base."""
    print("\n=== PRUEBA CONTROLADOR BASE ===")
    
    class ControladorPrueba(ControladorBase):
        async def _inicializar_impl(self):
            await asyncio.sleep(0.1)  # Simular inicialización
            return {'exito': True, 'mensaje': 'Controlador de prueba inicializado'}
    
    controlador = ControladorPrueba(ModeloMock(), "ControladorPrueba")
    
    # Probar inicialización
    resultado = await controlador.inicializar()
    print(f"Inicialización: {resultado}")
    
    # Probar métricas
    metricas = controlador.obtener_metricas()
    print(f"Métricas: {metricas}")
    
    # Probar verificación de salud
    salud = controlador.verificar_salud()
    print(f"Salud: {salud}")
    
    # Probar finalización
    resultado = await controlador.finalizar()
    print(f"Finalización: {resultado}")

def probar_gestor_configuracion():
    """Probar funcionalidad del gestor de configuración."""
    print("\n=== PRUEBA GESTOR CONFIGURACIÓN ===")
    
    gestor = GestorConfiguracion()
    
    # Probar obtener configuración
    version = gestor.obtener('sistema.version')
    print(f"Versión del sistema: {version}")
    
    # Probar establecer configuración
    exito = gestor.establecer('prueba.valor', 'test_value')
    print(f"Establecer configuración: {exito}")
    
    # Probar obtener el valor establecido
    valor = gestor.obtener('prueba.valor')
    print(f"Valor recuperado: {valor}")
    
    # Probar validación
    validacion = gestor.validar_configuracion()
    print(f"Validación: {validacion}")
    
    # Probar secciones
    seccion_sistema = gestor.obtener_seccion('sistema')
    print(f"Sección sistema: {list(seccion_sistema.keys())}")

async def probar_controlador_principal():
    """Probar funcionalidad del controlador principal."""
    print("\n=== PRUEBA CONTROLADOR PRINCIPAL ===")
    
    modelo = ModeloMock()
    vista = VistaMock()
    
    controlador = ControladorPrincipal(modelo, vista)
    
    # Probar inicialización
    resultado = await controlador.inicializar()
    print(f"Inicialización sistema: {resultado['exito']}")
    
    # Probar estado del sistema
    estado = controlador.obtener_estado_sistema_completo()
    print(f"Estado sistema - Controladores: {len(estado['controladores'])}")
    
    # Probar verificación de salud
    salud = controlador.verificar_salud_sistema()
    print(f"Salud sistema: {salud['estado_general']} - {salud['porcentaje_salud']}%")
    
    # Probar métricas
    metricas = controlador.obtener_metricas_sistema()
    print(f"Métricas sistema: {list(metricas.keys())}")
    
    # Probar obtener controlador específico
    controlador_escaneo = controlador.obtener_controlador('escaneo')
    print(f"Controlador escaneo disponible: {controlador_escaneo is not None}")
    
    # Probar finalización
    resultado = await controlador.finalizar()
    print(f"Finalización sistema: {resultado['exito']}")

def probar_controlador_escaneo():
    """Probar funcionalidad del controlador de escaneo."""
    print("\n=== PRUEBA CONTROLADOR ESCANEO ===")
    
    modelo = ModeloMock()
    controlador = ControladorEscaneo(modelo)
    
    # Probar estado del escaneo
    estado = controlador.obtener_estado_escaneo()
    print(f"Estado escaneo - Total realizados: {estado['total_escaneos_realizados']}")
    
    # Probar escaneo básico (localhost)
    print("Ejecutando escaneo básico de localhost...")
    resultado = controlador.ejecutar_escaneo_basico("127.0.0.1")
    if resultado['exito']:
        print(f"Escaneo básico exitoso - Tiempo: {resultado['resultados']['tiempo_ejecucion']}s")
    else:
        print(f"Error en escaneo básico: {resultado['error']}")
    
    # Probar logs de escaneo
    logs = controlador.obtener_logs_escaneo(5)
    print(f"Logs de escaneo: {len(logs)} eventos")

async def ejecutar_todas_las_pruebas():
    """Ejecutar todas las pruebas de forma secuencial."""
    print("🚀 INICIANDO PRUEBAS DE CONTROLADORES MEJORADOS")
    print("=" * 60)
    
    try:
        # Pruebas asíncronas
        await probar_controlador_base()
        await probar_controlador_principal()
        
        # Pruebas síncronas
        probar_gestor_configuracion()
        probar_controlador_escaneo()
        
        print("\n" + "=" * 60)
        print("✅ TODAS LAS PRUEBAS COMPLETADAS EXITOSAMENTE")
        
    except Exception as e:
        print(f"\n❌ ERROR EN PRUEBAS: {e}")
        import traceback
        traceback.print_exc()

if __name__ == "__main__":
    # Ejecutar pruebas
    asyncio.run(ejecutar_todas_las_pruebas())
