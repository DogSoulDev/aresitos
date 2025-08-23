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
                    callback_actualizacion(f"✓ COMPLETADO: {procesos_terminados} procesos SIEM terminados\n")
                else:
                    callback_actualizacion("• INFO: No se encontraron procesos SIEM activos\n")
                
                callback_actualizacion("=== SIEM DETENIDO COMPLETAMENTE ===\n\n")
                callback_habilitar()
                
            except Exception as e:
                callback_actualizacion(f"ERROR durante detención SIEM: {str(e)}\n")
                callback_habilitar()
        
        threading.Thread(target=ejecutar_detencion, daemon=True).start()
    
    def detener_monitoreo(self, callback_actualizacion: Callable, callback_habilitar: Callable):
        """Detener procesos de monitoreo de manera SEGURA y robusta."""
        def ejecutar_detencion():
            try:
                callback_actualizacion("=== DETENIENDO MONITOREO ARESITOS ===\n")
                callback_actualizacion("SEGURIDAD: Aplicando protecciones contra crash del sistema...\n")
                
                # Procesos de monitoreo específicos SEGUROS (solo herramientas, no servicios del sistema)
                procesos_monitoreo_seguros = [
                    'htop_aresitos', 'top_aresitos', 'iotop_aresitos', 
                    'nethogs_aresitos', 'iftop_aresitos'
                ]
                
                # IMPORTANTE: No incluir 'htop', 'top' etc genéricos que el usuario puede estar usando
                procesos_terminados = self._terminar_procesos_por_nombre(
                    procesos_monitoreo_seguros, callback_actualizacion, "MONITOREO-ARESITOS"
                )
                
                # Terminar SOLO procesos Python de ARESITOS con patrón muy específico
                procesos_terminados += self._terminar_procesos_python(
                    ['aresitos.*monitor', 'aresitos.*watch'], callback_actualizacion
                )
                
                # Limpiar SOLO archivos temporales de ARESITOS
                archivos_temp_seguros = [
                    '/tmp/aresitos_monitor.pid',
                    '/tmp/aresitos_system_monitor.log',
                    '/var/log/aresitos_monitor.log'
                ]
                self._limpiar_archivos_temporales(archivos_temp_seguros, callback_actualizacion)
                
                if procesos_terminados > 0:
                    callback_actualizacion(f"OK COMPLETADO: {procesos_terminados} procesos de monitoreo ARESITOS terminados\n")
                else:
                    callback_actualizacion("INFO: No se encontraron procesos de monitoreo ARESITOS activos\n")
                
                callback_actualizacion("=== MONITOREO ARESITOS DETENIDO COMPLETAMENTE ===\n")
                callback_actualizacion("SEGURIDAD: Sistema operativo protegido - no se tocaron procesos críticos\n\n")
                callback_habilitar()
                
            except Exception as e:
                callback_actualizacion(f"ERROR durante detención de monitoreo: {str(e)}\n")
                callback_actualizacion("SEGURIDAD: Error contenido - sistema protegido\n")
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
                    callback_actualizacion("✓ Monitores inotify FIM detenidos\n")
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
                    callback_actualizacion(f"✓ COMPLETADO: {procesos_terminados} procesos FIM terminados\n")
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
                    callback_actualizacion(f"✓ COMPLETADO: {procesos_terminados} procesos de escaneo cancelados\n")
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
                    callback_actualizacion(f"✓ COMPLETADO: {procesos_terminados} procesos de auditoría cancelados\n")
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
        """Terminar procesos por nombre de manera SEGURA y robusta."""
        procesos_terminados = 0
        
        # Lista de procesos CRÍTICOS del sistema que NUNCA deben terminarse
        procesos_protegidos = {
            'systemd', 'init', 'kernel', 'kthreadd', 'ksoftirqd', 'migration',
            'rcu_', 'watchdog', 'systemd-', 'dbus', 'NetworkManager', 'gdm',
            'Xorg', 'pulseaudio', 'bluetoothd', 'ssh', 'rsyslog', 'cron',
            'lightdm', 'gnome-shell', 'gnome-session', 'kali-session',
            'plasma', 'kwin', 'krunner', 'plasmashell'
        }
        
        for proceso in procesos:
            try:
                # VALIDACIÓN DE SEGURIDAD: Verificar que no es un proceso del sistema
                proceso_seguro = True
                for protegido in procesos_protegidos:
                    if protegido.lower() in proceso.lower():
                        callback_actualizacion(f"SEGURIDAD: Proceso {proceso} protegido - OMITIDO\n")
                        proceso_seguro = False
                        break
                
                if not proceso_seguro:
                    continue
                
                # Buscar procesos activos con validación adicional
                resultado = subprocess.run(['pgrep', '-f', proceso], 
                                        capture_output=True, text=True, timeout=5)
                if resultado.returncode == 0 and resultado.stdout.strip():
                    pids = resultado.stdout.strip().split('\n')
                    for pid in pids:
                        if pid.strip():
                            try:
                                pid_int = int(pid.strip())
                                
                                # VALIDACIÓN CRÍTICA: No tocar PID 1 (init) ni procesos de root críticos
                                if pid_int <= 10:  # PIDs 1-10 son típicamente críticos del sistema
                                    callback_actualizacion(f"SEGURIDAD: PID {pid_int} es crítico del sistema - OMITIDO\n")
                                    continue
                                
                                # Verificar que el proceso no es de root para servicios críticos
                                try:
                                    info_proceso = subprocess.run(['ps', '-p', str(pid_int), '-o', 'user,comm'], 
                                                                capture_output=True, text=True, timeout=3)
                                    if 'root' in info_proceso.stdout and any(critico in info_proceso.stdout.lower() 
                                                                           for critico in ['systemd', 'kernel', 'init']):
                                        callback_actualizacion(f"SEGURIDAD: Proceso root crítico PID {pid_int} - OMITIDO\n")
                                        continue
                                except:
                                    # Si no puede verificar, mejor ser conservador
                                    continue
                                
                                # Terminar proceso específico SOLO CON SIGTERM (nunca SIGKILL en sistema)
                                subprocess.run(['kill', '-TERM', str(pid_int)], 
                                            capture_output=True, timeout=3)
                                callback_actualizacion(f"OK Terminado {tipo} {proceso} (PID: {pid_int})\n")
                                procesos_terminados += 1
                                
                                # NO usar SIGKILL automáticamente - demasiado peligroso
                                time.sleep(0.5)
                                    
                            except (ValueError, subprocess.TimeoutExpired):
                                continue
                            except Exception as e:
                                callback_actualizacion(f"ADVERTENCIA: Error terminando PID {pid}: {str(e)}\n")
                                continue
            except subprocess.TimeoutExpired:
                callback_actualizacion(f"TIMEOUT: Búsqueda de proceso {proceso} cancelada por seguridad\n")
                continue
            except Exception as e:
                callback_actualizacion(f"ERROR: Búsqueda proceso {proceso}: {str(e)}\n")
                continue
        
        return procesos_terminados
    
    def _terminar_procesos_python(self, patrones: List[str], 
                                callback_actualizacion: Callable) -> int:
        """Terminar procesos Python específicos de manera SEGURA."""
        procesos_terminados = 0
        
        # Obtener PID actual y procesos padre para protección
        pid_actual = os.getpid()
        try:
            # Obtener el PID del proceso padre (ARESITOS principal)
            resultado_padre = subprocess.run(['ps', '-o', 'ppid=', '-p', str(pid_actual)], 
                                          capture_output=True, text=True, timeout=3)
            pid_padre = int(resultado_padre.stdout.strip()) if resultado_padre.stdout.strip() else None
        except:
            pid_padre = None
        
        for patron in patrones:
            try:
                # Buscar procesos con timeout de seguridad
                resultado = subprocess.run(['pgrep', '-f', patron], 
                                        capture_output=True, text=True, timeout=5)
                if resultado.returncode == 0 and resultado.stdout.strip():
                    pids = resultado.stdout.strip().split('\n')
                    for pid in pids:
                        if pid.strip():
                            try:
                                pid_int = int(pid.strip())
                                
                                # VALIDACIONES CRÍTICAS DE SEGURIDAD
                                # 1. No terminar proceso actual
                                if pid_int == pid_actual:
                                    callback_actualizacion(f"SEGURIDAD: PID {pid_int} es proceso actual - OMITIDO\n")
                                    continue
                                
                                # 2. No terminar proceso padre de ARESITOS
                                if pid_padre and pid_int == pid_padre:
                                    callback_actualizacion(f"SEGURIDAD: PID {pid_int} es proceso padre ARESITOS - OMITIDO\n")
                                    continue
                                
                                # 3. Verificar que es realmente un proceso Python de ARESITOS
                                try:
                                    info_proceso = subprocess.run(['ps', '-p', str(pid_int), '-o', 'cmd'], 
                                                                capture_output=True, text=True, timeout=3)
                                    cmd_line = info_proceso.stdout.lower()
                                    
                                    # Solo terminar si realmente contiene 'aresitos' o patrones seguros
                                    if not ('aresitos' in cmd_line or 'temp' in cmd_line or 'scan' in cmd_line):
                                        callback_actualizacion(f"SEGURIDAD: Proceso PID {pid_int} no parece ser de ARESITOS - OMITIDO\n")
                                        continue
                                        
                                    # No terminar intérpretes Python del sistema
                                    if any(sistema in cmd_line for sistema in ['/usr/bin/python', 'system', 'gnome', 'kde']):
                                        callback_actualizacion(f"SEGURIDAD: Python del sistema PID {pid_int} - OMITIDO\n")
                                        continue
                                        
                                except:
                                    # Si no puede verificar, mejor no tocar
                                    callback_actualizacion(f"SEGURIDAD: No se pudo verificar PID {pid_int} - OMITIDO\n")
                                    continue
                                
                                # Terminar proceso SOLO con SIGTERM
                                subprocess.run(['kill', '-TERM', str(pid_int)], 
                                            capture_output=True, timeout=3)
                                callback_actualizacion(f"OK Terminado proceso Python ARESITOS (PID: {pid_int})\n")
                                procesos_terminados += 1
                                
                            except (ValueError, subprocess.TimeoutExpired):
                                continue
                            except Exception as e:
                                callback_actualizacion(f"ADVERTENCIA: Error con PID {pid}: {str(e)}\n")
                                continue
            except subprocess.TimeoutExpired:
                callback_actualizacion(f"TIMEOUT: Búsqueda patrón {patron} cancelada por seguridad\n")
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
                    callback_actualizacion(f"✓ Limpiado archivo temporal: {archivo}\n")
            except Exception:
                pass

# Instancia global para uso en las vistas
detener_procesos = DetenerProcesos()
