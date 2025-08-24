#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Sistema unificado para detener procesos en Aresitos.
Creado por: DogSoulDev
Versión: 2.0.0 - Diciembre 2024
Licencia: Open Source Non-Commercial
"""

import subprocess
import os
import signal
import threading
import time
from typing import List, Dict, Optional, Callable

class DetenerProcesos:
    """Sistema unificado para detener procesos de manera robusta."""
    
    def __init__(self):
        self.procesos_detenidos = {}
        self.lock = threading.Lock()
    
    def detener_siem(self, callback_actualizacion: Callable, callback_habilitar: Callable):
        """Detener procesos SIEM de manera robusta."""
        def ejecutar_detencion():
            try:
                callback_actualizacion("=== DETENIENDO SIEM ===\n")
                
                # Procesos SIEM específicos
                procesos_siem = [
                    'elasticsearch', 'logstash', 'kibana', 'splunk', 
                    'ossec', 'wazuh', 'suricata', 'snort'
                ]
                
                procesos_terminados = self._terminar_procesos_por_nombre(
                    procesos_siem, callback_actualizacion, "SIEM"
                )
                
                # Terminar procesos Python relacionados con SIEM
                procesos_terminados += self._terminar_procesos_python(
                    ['python.*siem', 'python.*log'], callback_actualizacion
                )
                
                # Limpiar archivos temporales SIEM
                archivos_temp = [
                    '/tmp/siem_monitor.pid',
                    '/tmp/siem_events.log',
                    '/var/log/siem_analysis.log'
                ]
                self._limpiar_archivos_temporales(archivos_temp, callback_actualizacion)
                
                if procesos_terminados > 0:
                    callback_actualizacion(f"OK COMPLETADO: {procesos_terminados} procesos SIEM terminados\n")
                else:
                    callback_actualizacion("• INFO: No se encontraron procesos SIEM activos\n")
                
                callback_actualizacion("=== SIEM DETENIDO COMPLETAMENTE ===\n\n")
                callback_habilitar()
                
            except Exception as e:
                callback_actualizacion(f"ERROR durante detención SIEM: {str(e)}\n")
                callback_habilitar()
        
        threading.Thread(target=ejecutar_detencion, daemon=True).start()
    
    def detener_monitoreo(self, callback_actualizacion: Callable, callback_habilitar: Callable):
        """Detener procesos de monitoreo de manera robusta."""
        def ejecutar_detencion():
            try:
                callback_actualizacion("=== DETENIENDO MONITOREO ===\n")
                
                # Procesos de monitoreo específicos
                procesos_monitoreo = [
                    'htop', 'top', 'iotop', 'nethogs', 'iftop',
                    'vmstat', 'iostat', 'netstat', 'ss'
                ]
                
                procesos_terminados = self._terminar_procesos_por_nombre(
                    procesos_monitoreo, callback_actualizacion, "MONITOREO"
                )
                
                # Terminar procesos Python relacionados con monitoreo
                procesos_terminados += self._terminar_procesos_python(
                    ['python.*monitor', 'python.*watch'], callback_actualizacion
                )
                
                # Limpiar archivos temporales de monitoreo
                archivos_temp = [
                    '/tmp/monitor.pid',
                    '/tmp/system_monitor.log',
                    '/var/log/monitor.log'
                ]
                self._limpiar_archivos_temporales(archivos_temp, callback_actualizacion)
                
                if procesos_terminados > 0:
                    callback_actualizacion(f"OK COMPLETADO: {procesos_terminados} procesos de monitoreo terminados\n")
                else:
                    callback_actualizacion("• INFO: No se encontraron procesos de monitoreo activos\n")
                
                callback_actualizacion("=== MONITOREO DETENIDO COMPLETAMENTE ===\n\n")
                callback_habilitar()
                
            except Exception as e:
                callback_actualizacion(f"ERROR durante detención de monitoreo: {str(e)}\n")
                callback_habilitar()
        
        threading.Thread(target=ejecutar_detencion, daemon=True).start()
    
    def detener_fim(self, callback_actualizacion: Callable, callback_habilitar: Callable):
        """Detener procesos FIM de manera robusta."""
        def ejecutar_detencion():
            try:
                callback_actualizacion("=== DETENIENDO MONITOREO FIM ===\n")
                
                # Procesos FIM específicos
                procesos_fim = [
                    'inotifywait', 'auditd', 'aide', 'samhain', 'tripwire'
                ]
                
                procesos_terminados = self._terminar_procesos_por_nombre(
                    procesos_fim, callback_actualizacion, "FIM"
                )
                
                # Terminar procesos Python relacionados con FIM
                procesos_terminados += self._terminar_procesos_python(
                    ['python.*fim'], callback_actualizacion
                )
                
                # Detener monitores inotify específicos
                try:
                    subprocess.run(['pkill', '-f', 'inotifywait.*fim'], 
                                capture_output=True)
                    callback_actualizacion("OK Monitores inotify FIM detenidos\n")
                except Exception:
                    pass
                
                # Limpiar archivos temporales FIM
                archivos_temp = [
                    '/tmp/fim_monitor.pid',
                    '/tmp/fim_changes.log',
                    '/var/log/fim_monitor.log',
                    '/tmp/inotify_monitor.pid'
                ]
                self._limpiar_archivos_temporales(archivos_temp, callback_actualizacion)
                
                if procesos_terminados > 0:
                    callback_actualizacion(f"OK COMPLETADO: {procesos_terminados} procesos FIM terminados\n")
                else:
                    callback_actualizacion("• INFO: No se encontraron procesos FIM activos\n")
                
                callback_actualizacion("=== MONITOREO FIM DETENIDO COMPLETAMENTE ===\n\n")
                callback_habilitar()
                
            except Exception as e:
                callback_actualizacion(f"ERROR durante detención FIM: {str(e)}\n")
                callback_habilitar()
        
        threading.Thread(target=ejecutar_detencion, daemon=True).start()
    
    def cancelar_escaneo(self, callback_actualizacion: Callable, callback_habilitar: Callable):
        """Cancelar procesos de escaneo de manera robusta."""
        def ejecutar_cancelacion():
            try:
                callback_actualizacion("=== CANCELANDO ESCANEO ===\n")
                
                # Procesos de escaneo específicos
                procesos_escaneo = [
                    'nmap', 'masscan', 'zmap', 'rustscan', 'unicornscan',
                    'dirb', 'gobuster', 'dirbuster', 'ffuf', 'wfuzz',
                    'nikto', 'sqlmap', 'nuclei', 'whatweb'
                ]
                
                procesos_terminados = self._terminar_procesos_por_nombre(
                    procesos_escaneo, callback_actualizacion, "ESCANEO"
                )
                
                # Terminar procesos Python relacionados con escaneo
                procesos_terminados += self._terminar_procesos_python(
                    ['python.*scan', 'python.*enum'], callback_actualizacion
                )
                
                # Limpiar archivos temporales de escaneo
                archivos_temp = [
                    '/tmp/escaneo.pid',
                    '/tmp/scan_results.tmp',
                    '/var/log/scan.log'
                ]
                self._limpiar_archivos_temporales(archivos_temp, callback_actualizacion)
                
                if procesos_terminados > 0:
                    callback_actualizacion(f"OK COMPLETADO: {procesos_terminados} procesos de escaneo cancelados\n")
                else:
                    callback_actualizacion("• INFO: No se encontraron procesos de escaneo activos\n")
                
                callback_actualizacion("=== ESCANEO CANCELADO COMPLETAMENTE ===\n\n")
                callback_habilitar()
                
            except Exception as e:
                callback_actualizacion(f"ERROR durante cancelación de escaneo: {str(e)}\n")
                callback_habilitar()
        
        threading.Thread(target=ejecutar_cancelacion, daemon=True).start()
    
    def cancelar_auditoria(self, callback_actualizacion: Callable, callback_habilitar: Callable):
        """Cancelar procesos de auditoría de manera robusta."""
        def ejecutar_cancelacion():
            try:
                callback_actualizacion("=== CANCELANDO AUDITORÍA ===\n")
                
                # Procesos de auditoría específicos
                procesos_auditoria = [
                    'lynis', 'rkhunter', 'chkrootkit', 'nuclei', 'httpx',
                    'linpeas', 'pspy', 'clamav', 'clamscan'
                ]
                
                procesos_terminados = self._terminar_procesos_por_nombre(
                    procesos_auditoria, callback_actualizacion, "AUDITORIA"
                )
                
                # Terminar procesos Python relacionados con auditoría
                procesos_terminados += self._terminar_procesos_python(
                    ['python.*audit', 'python.*lynis'], callback_actualizacion
                )
                
                # Limpiar archivos temporales de auditoría
                archivos_temp = [
                    '/tmp/lynis.log',
                    '/tmp/rkhunter.log',
                    '/tmp/nuclei_output.txt',
                    '/tmp/auditoria_temp.log'
                ]
                self._limpiar_archivos_temporales(archivos_temp, callback_actualizacion)
                
                if procesos_terminados > 0:
                    callback_actualizacion(f"OK COMPLETADO: {procesos_terminados} procesos de auditoría cancelados\n")
                else:
                    callback_actualizacion("• INFO: No se encontraron procesos de auditoría activos\n")
                
                callback_actualizacion("=== AUDITORÍA CANCELADA COMPLETAMENTE ===\n\n")
                callback_habilitar()
                
            except Exception as e:
                callback_actualizacion(f"ERROR durante cancelación de auditoría: {str(e)}\n")
                callback_habilitar()
        
        threading.Thread(target=ejecutar_cancelacion, daemon=True).start()
    
    def _terminar_procesos_por_nombre(self, procesos: List[str], 
                                    callback_actualizacion: Callable, 
                                    tipo: str) -> int:
        """Terminar procesos por nombre de manera robusta."""
        procesos_terminados = 0
        
        for proceso in procesos:
            try:
                # Buscar procesos activos
                resultado = subprocess.run(['pgrep', '-f', proceso], 
                                        capture_output=True, text=True)
                if resultado.returncode == 0 and resultado.stdout.strip():
                    pids = resultado.stdout.strip().split('\n')
                    for pid in pids:
                        if pid.strip():
                            try:
                                # Terminar proceso específico
                                subprocess.run(['kill', '-TERM', pid.strip()], 
                                            capture_output=True)
                                callback_actualizacion(f"OK Terminado {tipo} {proceso} (PID: {pid.strip()})\n")
                                procesos_terminados += 1
                                
                                # Esperar un poco y verificar si sigue vivo
                                time.sleep(0.5)
                                resultado_check = subprocess.run(['kill', '-0', pid.strip()], 
                                                            capture_output=True)
                                if resultado_check.returncode == 0:
                                    # Aún vivo, usar SIGKILL
                                    subprocess.run(['kill', '-KILL', pid.strip()], 
                                                capture_output=True)
                                    callback_actualizacion(f"OK Forzado término de {proceso} (PID: {pid.strip()})\n")
                                    
                            except Exception:
                                continue
            except Exception:
                continue
        
        return procesos_terminados
    
    def _terminar_procesos_python(self, patrones: List[str], 
                                callback_actualizacion: Callable) -> int:
        """Terminar procesos Python específicos."""
        procesos_terminados = 0
        
        for patron in patrones:
            try:
                resultado = subprocess.run(['pgrep', '-f', patron], 
                                        capture_output=True, text=True)
                if resultado.returncode == 0 and resultado.stdout.strip():
                    pids = resultado.stdout.strip().split('\n')
                    for pid in pids:
                        if pid.strip() and pid.strip() != str(os.getpid()):
                            try:
                                subprocess.run(['kill', '-TERM', pid.strip()], 
                                            capture_output=True)
                                callback_actualizacion(f"OK Terminado proceso Python (PID: {pid.strip()})\n")
                                procesos_terminados += 1
                            except Exception:
                                continue
            except Exception:
                pass
        
        return procesos_terminados
    
    def _limpiar_archivos_temporales(self, archivos: List[str], 
                                   callback_actualizacion: Callable):
        """Limpiar archivos temporales."""
        for archivo in archivos:
            try:
                if os.path.exists(archivo):
                    os.remove(archivo)
                    callback_actualizacion(f"OK Limpiado archivo temporal: {archivo}\n")
            except Exception:
                pass

# Instancia global para uso en las vistas
detener_procesos = DetenerProcesos()
