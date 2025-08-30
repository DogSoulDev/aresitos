#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import subprocess
import os
import signal
import threading
import time
from typing import List, Dict, Optional, Callable

class DetenerProcesos:
    def __init__(self):
        self.procesos_detenidos = {}
        self.lock = threading.Lock()

    def detener_siem(self, callback_actualizacion: Callable, callback_habilitar: Callable):
        def ejecutar_detencion():
            try:
                callback_actualizacion("=== DETENIENDO SIEM ===\n")
                procesos_siem = [
                    'elasticsearch', 'logstash', 'kibana', 'splunk',
                    'ossec', 'wazuh', 'suricata', 'snort'
                ]
                procesos_terminados = self._terminar_procesos_por_nombre(
                    procesos_siem, callback_actualizacion, "SIEM"
                )
                procesos_terminados += self._terminar_procesos_python(
                    ['python.*siem', 'python.*log'], callback_actualizacion
                )
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
        def ejecutar_detencion():
            try:
                callback_actualizacion("=== DETENIENDO MONITOREO ===\n")
                procesos_monitoreo = [
                    'htop', 'top', 'iotop', 'nethogs', 'iftop',
                    'vmstat', 'iostat', 'netstat', 'ss'
                ]
                procesos_terminados = self._terminar_procesos_por_nombre(
                    procesos_monitoreo, callback_actualizacion, "MONITOREO"
                )
                procesos_terminados += self._terminar_procesos_python(
                    ['python.*monitor', 'python.*watch'], callback_actualizacion
                )
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
        def ejecutar_detencion():
            try:
                callback_actualizacion("=== DETENIENDO MONITOREO FIM ===\n")
                procesos_fim = [
                    'inotifywait', 'auditd', 'aide'
                ]
                procesos_terminados = self._terminar_procesos_por_nombre(
                    procesos_fim, callback_actualizacion, "FIM"
                )
                procesos_terminados += self._terminar_procesos_python(
                    ['python.*fim'], callback_actualizacion
                )
                try:
                    subprocess.run(['pkill', '-f', 'inotifywait.*fim'], capture_output=True)
                    callback_actualizacion("OK Monitores inotify FIM detenidos\n")
                except Exception:
                    pass
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
        def ejecutar_cancelacion():
            try:
                callback_actualizacion("=== CANCELANDO ESCANEO ===\n")
                procesos_escaneo = [
                    'nmap', 'masscan', 'zmap', 'rustscan', 'unicornscan',
                    'dirb', 'gobuster', 'dirbuster', 'ffuf', 'wfuzz',
                    'nikto', 'sqlmap', 'nuclei', 'whatweb'
                ]
                procesos_terminados = self._terminar_procesos_por_nombre(
                    procesos_escaneo, callback_actualizacion, "ESCANEO"
                )
                procesos_terminados += self._terminar_procesos_python(
                    ['python.*scan', 'python.*enum'], callback_actualizacion
                )
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
        def ejecutar_cancelacion():
            try:
                callback_actualizacion("=== CANCELANDO AUDITORÍA ===\n")
                procesos_auditoria = [
                    'lynis', 'rkhunter', 'chkrootkit', 'nuclei', 'httpx',
                    'linpeas', 'pspy', 'clamav', 'clamscan'
                ]
                procesos_terminados = self._terminar_procesos_por_nombre(
                    procesos_auditoria, callback_actualizacion, "AUDITORIA"
                )
                procesos_terminados += self._terminar_procesos_python(
                    ['python.*audit', 'python.*lynis'], callback_actualizacion
                )
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
                                    callback_actualizacion: Callable, tipo: str) -> int:
        procesos_terminados = 0
        # Lista extendida de procesos protegidos (no matar nunca)
        procesos_protegidos = [
            'systemd', 'init', 'login', 'sshd', 'Xorg', 'gdm', 'lightdm', 'NetworkManager',
            'dbus-daemon', 'udisksd', 'polkitd', 'upowerd', 'wpa_supplicant', 'gnome-shell',
            'plasmashell', 'xfce4-session', 'lxsession', 'openbox', 'kdeinit', 'kded', 'kdm',
            'sddm', 'agetty', 'bash', 'zsh', 'fish', 'pwsh', 'tmux', 'screen', 'python', 'python3',
            'konsole', 'gnome-terminal', 'xterm', 'tilix', 'alacritty', 'urxvt', 'mate-terminal',
            'terminator', 'lxterminal', 'xfce4-terminal', 'qterminal', 'eterm', 'rxvt', 'mlterm',
            'ttyd', 'vte', 'wayland', 'weston', 'Xwayland', 'startplasma-x11', 'startplasma-wayland',
            'startlxqt', 'startxfce4', 'startkde', 'startgnome', 'startmate', 'startdde',
            'gnome-session', 'kde-session', 'mate-session', 'lxqt-session', 'xfce4-session',
            'dbus-launch', 'dbus-run-session', 'X', 'Xwayland', 'wayland', 'weston',
            'gvfsd', 'gvfsd-fuse', 'at-spi2-registryd', 'at-spi-bus-launcher', 'pipewire',
            'pulseaudio', 'systemd-logind', 'systemd-userwork', 'colord', 'rtkit-daemon',
            'udisksd', 'upowerd', 'modem-manager', 'bluetoothd', 'wpa_supplicant',
            'gdm-session-worker', 'gdm-x-session', 'gdm-wayland-session', 'gdm3',
            'Xorg.bin', 'Xwayland.bin', 'Xorg.wrap', 'Xvfb', 'Xdummy', 'Xnest',
            'Xvnc', 'Xdmx', 'Xephyr', 'Xmir', 'Xvnc', 'Xvfb-run', 'Xsession',
            'Xsession.d', 'Xsession.options', 'Xsession.wrapper', 'Xsession-xsession',
            'Xsession-xinit', 'Xsession-xinitrc', 'Xsession-xinitrc.d', 'Xsession-xinitrc.options',
            'Xsession-xinitrc.wrapper', 'Xsession-xinitrc-xsession', 'Xsession-xinitrc-xinit',
            'Xsession-xinitrc-xinitrc', 'Xsession-xinitrc-xinitrc.d', 'Xsession-xinitrc-xinitrc.options',
            'Xsession-xinitrc-xinitrc.wrapper', 'Xsession-xinitrc-xinitrc-xsession',
            'Xsession-xinitrc-xinitrc-xinit', 'Xsession-xinitrc-xinitrc-xinitrc',
            'Xsession-xinitrc-xinitrc-xinitrc.d', 'Xsession-xinitrc-xinitrc-xinitrc.options',
            'Xsession-xinitrc-xinitrc-xinitrc.wrapper', 'Xsession-xinitrc-xinitrc-xinitrc-xsession',
            'Xsession-xinitrc-xinitrc-xinitrc-xinit', 'Xsession-xinitrc-xinitrc-xinitrc-xinitrc',
            'Xsession-xinitrc-xinitrc-xinitrc-xinitrc.d', 'Xsession-xinitrc-xinitrc-xinitrc-xinitrc.options',
            'Xsession-xinitrc-xinitrc-xinitrc-xinitrc.wrapper', 'Xsession-xinitrc-xinitrc-xinitrc-xinitrc-xsession',
            'Xsession-xinitrc-xinitrc-xinitrc-xinitrc-xinit', 'Xsession-xinitrc-xinitrc-xinitrc-xinitrc-xinitrc',
            'Xsession-xinitrc-xinitrc-xinitrc-xinitrc-xinitrc.d', 'Xsession-xinitrc-xinitrc-xinitrc-xinitrc-xinitrc.options',
            'Xsession-xinitrc-xinitrc-xinitrc-xinitrc-xinitrc.wrapper'
        ]
        usuario_actual = os.getenv('USER') or os.getenv('USERNAME')
        for proceso in procesos:
            try:
                resultado = subprocess.run(['pgrep', '-af', proceso], capture_output=True, text=True)
                if resultado.returncode == 0 and resultado.stdout.strip():
                    lineas = resultado.stdout.strip().split('\n')
                    for linea in lineas:
                        partes = linea.strip().split()
                        if not partes:
                            continue
                        pid = partes[0]
                        comando = ' '.join(partes[1:])
                        # Protección: no terminar procesos críticos ni de sesión
                        if any(p in comando for p in procesos_protegidos):
                            callback_actualizacion(f"PROTEGIDO: {comando} (PID: {pid}) no será terminado por seguridad\n")
                            continue
                        # Protección extra: no matar procesos con DISPLAY/XDG_SESSION/TTY de usuario
                        try:
                            environ = subprocess.check_output(['cat', f'/proc/{pid}/environ']).decode(errors='ignore')
                            if 'DISPLAY=' in environ or 'XDG_SESSION' in environ or 'WAYLAND_DISPLAY' in environ or 'TTY=' in environ:
                                callback_actualizacion(f"PROTEGIDO: {comando} (PID: {pid}) tiene entorno gráfico/terminal, no será terminado\n")
                                continue
                        except Exception:
                            pass
                        # Log explícito antes de matar
                        callback_actualizacion(f"ADVERTENCIA: Terminando {comando} (PID: {pid}) por petición de usuario\n")
                        # Protección: no terminar procesos de root ni del usuario de sesión
                        user = None
                        try:
                            import sys
                            if sys.platform.startswith('linux'):
                                def _get_user_by_uid(uid):
                                    try:
                                        import pwd
                                        if hasattr(pwd, 'getpwuid'):
                                            return pwd.getpwuid(uid).pw_name  # type: ignore[attr-defined]
                                    except Exception:
                                        pass
                                    return None
                                try:
                                    uid = int(subprocess.check_output(['ps', '-o', 'uid=', '-p', pid]).decode().strip())
                                    user = _get_user_by_uid(uid)
                                except Exception:
                                    user = None
                        except Exception:
                            user = None
                        if user and user in ['root', usuario_actual]:
                            callback_actualizacion(f"PROTEGIDO: Proceso de usuario crítico ({user}) {comando} (PID: {pid}) no será terminado\n")
                            continue
                        try:
                            subprocess.run(['kill', '-TERM', pid], capture_output=True)
                            callback_actualizacion(f"OK Terminado {tipo} {proceso} (PID: {pid})\n")
                            procesos_terminados += 1
                            time.sleep(0.5)
                            resultado_check = subprocess.run(['kill', '-0', pid], capture_output=True)
                            if resultado_check.returncode == 0:
                                subprocess.run(['kill', '-KILL', pid], capture_output=True)
                                callback_actualizacion(f"OK Forzado término de {proceso} (PID: {pid})\n")
                        except Exception as e:
                            callback_actualizacion(f"ERROR al terminar {comando} (PID: {pid}): {str(e)}\n")
            except Exception as e:
                callback_actualizacion(f"ERROR general al buscar/terminar procesos: {str(e)}\n")
        return procesos_terminados
    
    def _terminar_procesos_python(self, patrones: List[str], 
                                callback_actualizacion: Callable) -> int:
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
        for archivo in archivos:
            try:
                if os.path.exists(archivo):
                    os.remove(archivo)
                    callback_actualizacion(f"OK Limpiado archivo temporal: {archivo}\n")
            except Exception:
                pass

# Instancia global para uso en las vistas
detener_procesos = DetenerProcesos()
