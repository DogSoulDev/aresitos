#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ARESITOS v3.0 - Renombrador de Proyecto: Aresitos → aresitos
============================================================

Script para cambiar sistemáticamente todas las referencias de "Aresitos" 
a "aresitos" en el proyecto completo.

Principios ARESITOS aplicados:
1. Automatización - Cambio automatizado en todo el proyecto
2. Robustez - Backup y validación de cambios
3. Eficiencia - Procesamiento optimizado de archivos
4. Seguridad - Validación y verificación de cambios
5. Integración - Preservar funcionalidad del sistema
6. Transparencia - Logs detallados de todos los cambios
7. Optimización - Procesamiento eficiente de archivos
8. Simplicidad - Interfaz clara y proceso directo

IMPORTANTE: Este script cambiarán las referencias a carpeta/módulo pero NO 
renombra físicamente la carpeta. Eso debe hacerse manualmente después.

Autor: DogSoulDev
Fecha: Agosto 2025
"""

import os
import sys
import re
import shutil
import datetime
from pathlib import Path
from typing import List, Dict, Tuple

class RenombradorAresitos:
    """Renombrador sistemático de proyecto ARESITOS."""
    
    def __init__(self):
        self.ruta_proyecto = Path("c:/Users/dogso/Desktop/Aresitos")
        self.archivos_modificados = []
        self.cambios_realizados = []
        self.errores_encontrados = []
        self.backup_dir = None
        
        # Patrones de cambio - solo referencias a nombres, NO URLs de GitHub
        self.patrones_cambio = [
            # Imports de Python (CRÍTICO)
            (r'from Aresitos\.', r'from aresitos.'),
            (r'import Aresitos\.', r'import aresitos.'),
            (r'__import__\([\'"]Aresitos\.', r'__import__(\'aresitos.'),
            
            # Paths en archivos de configuración (CRÍTICO)
            (r'"Aresitos\.', r'"aresitos.'),
            (r"'Aresitos\.", r"'aresitos."),
            (r'aresitos/', r'aresitos/'),
            
            # Referencias en pyproject.toml (CRÍTICO)
            (r'packages = \["Aresitos"\]', r'packages = ["aresitos"]'),
            (r'known_first_party = \["Aresitos"\]', r'known_first_party = ["aresitos"]'),
            (r'testpaths = \["tests", "aresitos/tests"\]', r'testpaths = ["tests", "aresitos/tests"]'),
            (r'source = \["Aresitos"\]', r'source = ["aresitos"]'),
            
            # Referencias en scripts shell
            (r'/aresitos/', r'/aresitos/'),
            
            # Referencias en logs y paths internos
            (r'logs/aresitos\.log', r'logs/aresitos.log'),  # Mantener logs en minúscula
            (r'data/aresitos\.', r'data/aresitos.'),  # Mantener data en minúscula
        ]
        
        # URLs y nombres que NO deben cambiarse (GitHub, títulos, etc.)
        self.exclusiones = [
            r'github\.com/DogSoulDev/Aresitos',  # URLs de GitHub
            r'DogSoulDev/Aresitos\.git',  # URLs de git
            r'# ARESITOS',  # Títulos en comentarios
            r'ARESITOS v',  # Versiones
            r'Sistema.*ARESITOS',  # Descripciones de sistema
            r'Herramienta.*ARESITOS',  # Descripciones
            r'LoginAresitos',  # Nombres de clases específicas
            r'title="Aresitos"',  # Títulos de ventanas
        ]
        
        # Tipos de archivo a procesar
        self.extensiones_procesar = {'.py', '.toml', '.md', '.txt', '.sh', '.json', '.gitkeep'}
        
        # Archivos que requieren atención especial
        self.archivos_criticos = [
            'main.py',
            'pyproject.toml', 
            'requirements.txt',
            '__init__.py'
        ]
    
    def crear_backup(self) -> bool:
        """Crear backup del proyecto antes de modificar."""
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            self.backup_dir = self.ruta_proyecto.parent / f"Aresitos_backup_{timestamp}"
            
            print(f"🔄 Creando backup en: {self.backup_dir}")
            shutil.copytree(self.ruta_proyecto, self.backup_dir)
            print("✅ Backup creado exitosamente")
            return True
            
        except Exception as e:
            print(f"❌ ERROR creando backup: {e}")
            return False
    
    def debe_procesar_archivo(self, archivo_path: Path) -> bool:
        """Determinar si un archivo debe ser procesado."""
        # Verificar extensión
        if archivo_path.suffix not in self.extensiones_procesar:
            return False
        
        # Excluir directorios específicos
        partes_path = archivo_path.parts
        exclusiones_dir = {'.git', '__pycache__', '.pytest_cache', 'node_modules'}
        
        if any(exclusion in partes_path for exclusion in exclusiones_dir):
            return False
        
        # Verificar que el archivo existe y es legible
        try:
            if archivo_path.is_file() and archivo_path.stat().st_size > 0:
                return True
        except:
            pass
        
        return False
    
    def debe_excluir_linea(self, linea: str) -> bool:
        """Verificar si una línea debe ser excluida del cambio."""
        for exclusion in self.exclusiones:
            if re.search(exclusion, linea, re.IGNORECASE):
                return True
        return False
    
    def procesar_archivo(self, archivo_path: Path) -> bool:
        """Procesar un archivo individual."""
        try:
            print(f"📝 Procesando: {archivo_path.relative_to(self.ruta_proyecto)}")
            
            # Leer archivo con diferentes encodings
            contenido_original = None
            encoding_usado = None
            
            for encoding in ['utf-8', 'latin1', 'cp1252']:
                try:
                    with open(archivo_path, 'r', encoding=encoding) as f:
                        contenido_original = f.read()
                    encoding_usado = encoding
                    break
                except UnicodeDecodeError:
                    continue
            
            if contenido_original is None:
                print(f"⚠️ WARNING: No se pudo leer {archivo_path}")
                return False
            
            contenido_modificado = contenido_original
            cambios_en_archivo = 0
            
            # Aplicar patrones línea por línea para mejor control
            lineas = contenido_original.split('\n')
            lineas_modificadas = []
            
            for num_linea, linea in enumerate(lineas, 1):
                linea_original = linea
                
                # Verificar exclusiones
                if self.debe_excluir_linea(linea):
                    lineas_modificadas.append(linea)
                    continue
                
                # Aplicar patrones de cambio
                linea_modificada = linea
                for patron, reemplazo in self.patrones_cambio:
                    if re.search(patron, linea_modificada):
                        nueva_linea = re.sub(patron, reemplazo, linea_modificada)
                        if nueva_linea != linea_modificada:
                            print(f"   📍 Línea {num_linea}: {patron}")
                            print(f"      Antes: {linea_modificada.strip()}")
                            print(f"      Después: {nueva_linea.strip()}")
                            linea_modificada = nueva_linea
                            cambios_en_archivo += 1
                            
                            # Registrar cambio
                            self.cambios_realizados.append({
                                'archivo': str(archivo_path.relative_to(self.ruta_proyecto)),
                                'linea': num_linea,
                                'antes': linea_original.strip(),
                                'despues': linea_modificada.strip(),
                                'patron': patron
                            })
                
                lineas_modificadas.append(linea_modificada)
            
            # Solo escribir si hubo cambios
            if cambios_en_archivo > 0:
                contenido_final = '\n'.join(lineas_modificadas)
                
                with open(archivo_path, 'w', encoding=encoding_usado) as f:
                    f.write(contenido_final)
                
                self.archivos_modificados.append(str(archivo_path.relative_to(self.ruta_proyecto)))
                print(f"   ✅ {cambios_en_archivo} cambios aplicados")
                return True
            else:
                print(f"   ℹ️ Sin cambios necesarios")
                return False
                
        except Exception as e:
            error_msg = f"Error procesando {archivo_path}: {e}"
            print(f"   ❌ {error_msg}")
            self.errores_encontrados.append(error_msg)
            return False
    
    def ejecutar_renombramiento(self):
        """Ejecutar el proceso completo de renombramiento."""
        print("🏗️ ARESITOS v3.0 - RENOMBRADOR DE PROYECTO")
        print("=" * 60)
        print(f"📅 Fecha: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"🎯 Objetivo: Cambiar Aresitos → aresitos en todo el proyecto")
        print(f"📁 Directorio: {self.ruta_proyecto}")
        print()
        
        # Verificar directorio existe
        if not self.ruta_proyecto.exists():
            print(f"❌ ERROR: Directorio no encontrado: {self.ruta_proyecto}")
            return False
        
        # Crear backup
        if not self.crear_backup():
            respuesta = input("⚠️ No se pudo crear backup. ¿Continuar? (s/N): ")
            if respuesta.lower() != 's':
                print("❌ Operación cancelada por el usuario")
                return False
        
        print("\n🔍 Escaneando archivos...")
        archivos_a_procesar = []
        
        # Encontrar todos los archivos a procesar
        for archivo_path in self.ruta_proyecto.rglob('*'):
            if self.debe_procesar_archivo(archivo_path):
                archivos_a_procesar.append(archivo_path)
        
        print(f"📊 Archivos encontrados: {len(archivos_a_procesar)}")
        
        if not archivos_a_procesar:
            print("⚠️ WARNING: No se encontraron archivos para procesar")
            return False
        
        # Confirmar operación
        print(f"\n📋 ARCHIVOS A PROCESAR:")
        for archivo in sorted(archivos_a_procesar[:10]):  # Mostrar primeros 10
            print(f"   • {archivo.relative_to(self.ruta_proyecto)}")
        
        if len(archivos_a_procesar) > 10:
            print(f"   ... y {len(archivos_a_procesar) - 10} archivos más")
        
        print(f"\n⚠️ IMPORTANTE:")
        print(f"   • Se crearán backups automáticamente")
        print(f"   • Se cambiarán imports de Python")
        print(f"   • Se cambiarán paths en configuración")
        print(f"   • NO se cambiarán URLs de GitHub")
        print(f"   • La carpeta física NO se renombra automáticamente")
        print()
        
        respuesta = input("🤔 ¿Continuar con el renombramiento? (s/N): ")
        if respuesta.lower() != 's':
            print("❌ Operación cancelada por el usuario")
            return False
        
        # Procesar archivos
        print(f"\n🔄 Procesando archivos...")
        archivos_procesados = 0
        archivos_modificados_count = 0
        
        for archivo_path in archivos_a_procesar:
            if self.procesar_archivo(archivo_path):
                archivos_modificados_count += 1
            archivos_procesados += 1
        
        # Generar reporte final
        self.generar_reporte_final(archivos_procesados, archivos_modificados_count)
        
        return True
    
    def generar_reporte_final(self, archivos_procesados: int, archivos_modificados_count: int):
        """Generar reporte final del proceso."""
        print(f"\n" + "=" * 60)
        print(f"📊 REPORTE FINAL DEL RENOMBRAMIENTO")
        print(f"=" * 60)
        
        print(f"📁 Archivos procesados: {archivos_procesados}")
        print(f"📝 Archivos modificados: {archivos_modificados_count}")
        print(f"🔧 Cambios totales realizados: {len(self.cambios_realizados)}")
        print(f"❌ Errores encontrados: {len(self.errores_encontrados)}")
        
        if self.backup_dir:
            print(f"💾 Backup disponible en: {self.backup_dir}")
        
        # Mostrar archivos modificados
        if self.archivos_modificados:
            print(f"\n✅ ARCHIVOS MODIFICADOS:")
            for archivo in sorted(self.archivos_modificados)[:15]:
                print(f"   • {archivo}")
            if len(self.archivos_modificados) > 15:
                print(f"   ... y {len(self.archivos_modificados) - 15} archivos más")
        
        # Mostrar errores si los hay
        if self.errores_encontrados:
            print(f"\n⚠️ ERRORES ENCONTRADOS:")
            for error in self.errores_encontrados[:5]:
                print(f"   • {error}")
            if len(self.errores_encontrados) > 5:
                print(f"   ... y {len(self.errores_encontrados) - 5} errores más")
        
        # Guardar reporte detallado
        self.guardar_reporte_detallado()
        
        # Instrucciones finales
        print(f"\n🎯 PRÓXIMOS PASOS REQUERIDOS:")
        print(f"=" * 60)
        print(f"1. 📁 Renombrar físicamente la carpeta:")
        print(f"   Windows: ren Aresitos aresitos")
        print(f"   Linux: mv Aresitos aresitos")
        print()
        print(f"2. 🔄 Actualizar repositorio Git:")
        print(f"   git add .")
        print(f"   git commit -m 'Renombrar proyecto Aresitos → aresitos'")
        print()
        print(f"3. 🧪 Verificar funcionamiento:")
        print(f"   cd aresitos")
        print(f"   python main.py")
        print()
        print(f"4. 📚 Revisar archivos críticos:")
        for critico in self.archivos_criticos:
            if critico in [Path(a).name for a in self.archivos_modificados]:
                print(f"   • {critico} ✅ (modificado)")
            else:
                print(f"   • {critico} ℹ️ (sin cambios)")
        
        resultado = "EXITOSO" if len(self.errores_encontrados) == 0 else "PARCIAL"
        print(f"\n🏆 RESULTADO: {resultado}")
        
        if len(self.errores_encontrados) == 0:
            print(f"🎉 ¡Renombramiento completado exitosamente!")
        else:
            print(f"⚠️ Renombramiento completado con advertencias")
        
        print(f"=" * 60)
    
    def guardar_reporte_detallado(self):
        """Guardar reporte detallado en archivo."""
        try:
            timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
            nombre_reporte = f"reporte_renombramiento_{timestamp}.txt"
            
            with open(nombre_reporte, 'w', encoding='utf-8') as f:
                f.write("REPORTE DETALLADO - RENOMBRAMIENTO ARESITOS\n")
                f.write("=" * 50 + "\n\n")
                f.write(f"Fecha: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                f.write(f"Directorio: {self.ruta_proyecto}\n")
                f.write(f"Backup: {self.backup_dir}\n\n")
                
                f.write("CAMBIOS REALIZADOS:\n")
                f.write("-" * 20 + "\n")
                for cambio in self.cambios_realizados:
                    f.write(f"Archivo: {cambio['archivo']}\n")
                    f.write(f"Línea: {cambio['linea']}\n")
                    f.write(f"Patrón: {cambio['patron']}\n")
                    f.write(f"Antes: {cambio['antes']}\n")
                    f.write(f"Después: {cambio['despues']}\n\n")
                
                if self.errores_encontrados:
                    f.write("ERRORES ENCONTRADOS:\n")
                    f.write("-" * 20 + "\n")
                    for error in self.errores_encontrados:
                        f.write(f"• {error}\n")
            
            print(f"💾 Reporte detallado guardado: {nombre_reporte}")
            
        except Exception as e:
            print(f"⚠️ WARNING: No se pudo guardar reporte detallado: {e}")

def main():
    """Función principal."""
    try:
        renombrador = RenombradorAresitos()
        
        # Mostrar información inicial
        print("⚠️ IMPORTANTE: LEER ANTES DE CONTINUAR")
        print("=" * 50)
        print("Este script cambiará TODAS las referencias de 'Aresitos' a 'aresitos'")
        print("en el código fuente, pero NO renombrará físicamente la carpeta.")
        print()
        print("Cambios que se realizarán:")
        print("• Imports Python: from aresitos. → from aresitos.")
        print("• Paths en configuración: aresitos/ → aresitos/")
        print("• Referencias en pyproject.toml")
        print("• Referencias en documentación (paths)")
        print()
        print("NO se cambiarán:")
        print("• URLs de GitHub (requieren renombrar repositorio)")
        print("• Títulos y descripciones de sistema")
        print("• Nombres de clases específicas")
        print()
        
        respuesta = input("¿Entendido y deseas continuar? (s/N): ")
        if respuesta.lower() != 's':
            print("❌ Operación cancelada")
            return 0
        
        # Ejecutar renombramiento
        if renombrador.ejecutar_renombramiento():
            return 0
        else:
            return 1
            
    except KeyboardInterrupt:
        print("\n⚠️ Operación cancelada por el usuario")
        return 1
    except Exception as e:
        print(f"❌ ERROR CRÍTICO: {e}")
        return 1

if __name__ == "__main__":
    sys.exit(main())
