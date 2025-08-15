# -*- coding: utf-8 -*-

import subprocess
from ares_aegis.modelo.modelo_utilidades_sistema import ModeloUtilidadesSistema

class ControladorAuditoria:
    
    def __init__(self, modelo_principal):
        self.modelo_principal = modelo_principal
        self.utilidades_sistema = ModeloUtilidadesSistema()
    
    def ejecutar_auditoria_lynis(self):
        return self.utilidades_sistema.ejecutar_auditoria_completa_lynis()
    
    def ejecutar_deteccion_rootkits(self):
        return self.utilidades_sistema.ejecutar_deteccion_rootkits_completa()
    
    def verificar_permisos_criticos(self):
        return self.utilidades_sistema.verificar_permisos_archivos_criticos_avanzado()
    
    def analizar_servicios_sistema(self):
        return self.utilidades_sistema.analizar_servicios_sistema_avanzado()
    
    def obtener_informacion_sistema(self):
        return self.utilidades_sistema.obtener_info_hardware_completa()
    
    def ejecutar_auditoria_completa(self):
        resultados = {}
        
        try:
            resultados['lynis'] = self.ejecutar_auditoria_lynis()
        except Exception as e:
            resultados['lynis'] = {'exito': False, 'error': str(e)}
        
        try:
            resultados['rootkits'] = self.ejecutar_deteccion_rootkits()
        except Exception as e:
            resultados['rootkits'] = {'exito': False, 'error': str(e)}
        
        try:
            resultados['permisos'] = self.verificar_permisos_criticos()
        except Exception as e:
            resultados['permisos'] = {'exito': False, 'error': str(e)}
        
        try:
            resultados['servicios'] = self.analizar_servicios_sistema()
        except Exception as e:
            resultados['servicios'] = {'exito': False, 'error': str(e)}
        
        return {
            'exito': True,
            'resultados': resultados,
            'resumen': self._generar_resumen_auditoria(resultados)
        }
    
    def _generar_resumen_auditoria(self, resultados):
        total_checks = len(resultados)
        exitosos = sum(1 for r in resultados.values() if r.get('exito', False))
        
        return {
            'total_verificaciones': total_checks,
            'exitosas': exitosos,
            'fallidas': total_checks - exitosos,
            'porcentaje_exito': (exitosos / total_checks * 100) if total_checks > 0 else 0
        }

    def verificar_funcionalidad_kali(self):
        """
        Verificar que todas las funcionalidades de auditoría funcionen en Kali Linux.
        """
        from datetime import datetime
        
        resultado = {
            'timestamp': datetime.now().isoformat(),
            'sistema_operativo': None,
            'gestor_permisos': False,
            'herramientas_disponibles': {},
            'permisos_sudo': False,
            'funcionalidad_completa': False,
            'recomendaciones': []
        }
        
        try:
            import platform
            resultado['sistema_operativo'] = platform.system()
            
            # Verificar gestor de permisos
            if self.modelo_principal and hasattr(self.modelo_principal, 'gestor_permisos'):
                if self.modelo_principal.gestor_permisos is not None:
                    resultado['gestor_permisos'] = True
                    
                    # Verificar permisos sudo si está disponible
                    try:
                        resultado['permisos_sudo'] = self.modelo_principal.gestor_permisos.verificar_sudo_disponible()
                    except Exception:
                        resultado['permisos_sudo'] = False
                    
                    # Verificar herramientas específicas de Auditoría
                    herramientas = ['lynis', 'rkhunter', 'chkrootkit', 'systemctl']
                    for herramienta in herramientas:
                        estado = self.modelo_principal.gestor_permisos.verificar_permisos_herramienta(herramienta)
                        resultado['herramientas_disponibles'][herramienta] = estado
            
            # Evaluar funcionalidad completa
            herramientas_ok = sum(1 for h in resultado['herramientas_disponibles'].values() 
                                if h.get('disponible', False) and h.get('permisos_ok', False))
            
            resultado['funcionalidad_completa'] = (
                resultado['gestor_permisos'] and 
                resultado['permisos_sudo'] and 
                herramientas_ok >= 2  # Al menos 2 herramientas de auditoría
            )
            
            # Generar recomendaciones
            if not resultado['funcionalidad_completa']:
                if not resultado['gestor_permisos']:
                    resultado['recomendaciones'].append("Gestor de permisos no disponible")
                
                if not resultado['permisos_sudo']:
                    resultado['recomendaciones'].append("Ejecutar: sudo ./configurar_kali.sh")
                
                if herramientas_ok < 2:
                    resultado['recomendaciones'].append("Instalar herramientas auditoría: sudo apt install lynis rkhunter chkrootkit")
            
        except Exception as e:
            resultado['error'] = str(e)
        
        return resultado

# RESUMEN TÉCNICO: Controlador de auditorías de seguridad para Kali Linux. Coordina 
# análisis de sistema con lynis, detección de rootkits, verificación de permisos y 
# servicios. Arquitectura MVC con principios SOLID, herramientas nativas sin 
# dependencias externas, optimizado para auditorías de seguridad profesionales.
