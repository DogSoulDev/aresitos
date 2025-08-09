# -*- coding: utf-8 -*-

import os
import shutil
import time
import hashlib
import platform
import json
import datetime
import subprocess
import signal
from typing import Dict, List, Any, Optional
from pathlib import Path

class Cuarentena:
    def __init__(self):
        self.es_kali = self._detectar_kali()
        self.directorio_cuarentena = self._crear_directorio_cuarentena()
        self.directorio_metadata = self._crear_directorio_metadata()
        self.archivo_registro = None
        if self.directorio_metadata:
            self.archivo_registro = os.path.join(self.directorio_metadata, "registro_cuarentena.json")
        self.procesos_monitoreados = {}
        self._cargar_registro()
    
    def _detectar_kali(self) -> bool:
        if platform.system() != "Linux":
            return False
        try:
            with open('/etc/os-release', 'r') as f:
                contenido = f.read().lower()
                return any(distro in contenido for distro in ['kali', 'debian', 'ubuntu'])
        except:
            return False
    
    def _crear_directorio_cuarentena(self) -> Optional[str]:
        if self.es_kali:
            directorio = "/var/lib/aresitos/cuarentena"
        else:
            directorio = os.path.join(os.path.expanduser("~"), ".aresitos", "cuarentena")
        
        try:
            os.makedirs(directorio, mode=0o700, exist_ok=True)
            return directorio
        except Exception:
            # Fallback a directorio temporal
            try:
                directorio_fallback = os.path.join("/tmp", "aresitos_cuarentena")
                os.makedirs(directorio_fallback, mode=0o700, exist_ok=True)
                return directorio_fallback
            except:
                return None
    
    def _crear_directorio_metadata(self) -> Optional[str]:
        if not self.directorio_cuarentena:
            return None
        
        directorio_meta = os.path.join(self.directorio_cuarentena, ".metadata")
        try:
            os.makedirs(directorio_meta, mode=0o700, exist_ok=True)
            return directorio_meta
        except:
            return None
    
    def _cargar_registro(self):
        self.archivos_cuarentena = []
        if self.archivo_registro and os.path.exists(self.archivo_registro):
            try:
                with open(self.archivo_registro, 'r') as f:
                    data = json.load(f)
                    self.archivos_cuarentena = data.get('archivos', [])
            except:
                self.archivos_cuarentena = []
    
    def _guardar_registro(self):
        if not self.archivo_registro:
            return False
        
        try:
            data = {
                'version': '1.0',
                'timestamp': datetime.datetime.now().isoformat(),
                'archivos': self.archivos_cuarentena
            }
            
            with open(self.archivo_registro, 'w') as f:
                json.dump(data, f, indent=2, default=str)
            return True
        except:
            return False
    
    def _calcular_hash_archivo(self, ruta_archivo: str) -> str:
        try:
            hasher = hashlib.sha256()
            with open(ruta_archivo, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except:
            return hashlib.sha256(ruta_archivo.encode()).hexdigest()
    
    def _obtener_metadata_archivo(self, ruta_archivo: str) -> Dict[str, Any]:
        try:
            stat = os.stat(ruta_archivo)
            
            metadata = {
                'tamaño': stat.st_size,
                'permisos': oct(stat.st_mode)[-3:],
                'propietario_uid': stat.st_uid,
                'grupo_gid': stat.st_gid,
                'fecha_creacion': datetime.datetime.fromtimestamp(stat.st_ctime).isoformat(),
                'fecha_modificacion': datetime.datetime.fromtimestamp(stat.st_mtime).isoformat(),
                'fecha_acceso': datetime.datetime.fromtimestamp(stat.st_atime).isoformat()
            }
            
            # Obtener información adicional en Linux
            if self.es_kali:
                metadata.update(self._obtener_metadata_linux_avanzada(ruta_archivo))
            
            return metadata
        except Exception as e:
            return {'error': str(e)}
    
    def _obtener_metadata_linux_avanzada(self, ruta_archivo: str) -> Dict[str, Any]:
        metadata_avanzada = {}
        
        try:
            # Usar 'file' para detectar tipo de archivo
            cmd = ['file', '-b', ruta_archivo]
            resultado = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if resultado.returncode == 0:
                metadata_avanzada['tipo_archivo'] = resultado.stdout.strip()
        except:
            pass
        
        try:
            # Verificar si es ejecutable
            metadata_avanzada['es_ejecutable'] = os.access(ruta_archivo, os.X_OK)
            
            # Verificar si tiene setuid/setgid
            stat = os.stat(ruta_archivo)
            metadata_avanzada['setuid'] = bool(stat.st_mode & 0o4000)
            metadata_avanzada['setgid'] = bool(stat.st_mode & 0o2000)
            metadata_avanzada['sticky'] = bool(stat.st_mode & 0o1000)
        except:
            pass
        
        return metadata_avanzada
    
    def poner_en_cuarentena(self, ruta_archivo: str, motivo: str = "Archivo sospechoso", 
                           nivel_amenaza: str = "MEDIO", fuente_deteccion: str = "MANUAL") -> Dict[str, Any]:
        if not self.directorio_cuarentena:
            return {"exito": False, "error": "Sistema de cuarentena no disponible"}
        
        if not os.path.exists(ruta_archivo):
            return {"exito": False, "error": "Archivo no existe"}
        
        try:
            # Calcular hash del archivo
            hash_archivo = self._calcular_hash_archivo(ruta_archivo)
            
            # Verificar si ya está en cuarentena
            for registro in self.archivos_cuarentena:
                if registro['hash_sha256'] == hash_archivo:
                    return {"exito": False, "error": "Archivo ya está en cuarentena"}
            
            # Obtener metadata del archivo
            metadata = self._obtener_metadata_archivo(ruta_archivo)
            
            # Crear nombre único para cuarentena
            timestamp = str(int(time.time()))
            extension = Path(ruta_archivo).suffix
            nombre_cuarentena = f"{timestamp}_{hash_archivo[:16]}{extension}"
            ruta_cuarentena = os.path.join(self.directorio_cuarentena, nombre_cuarentena)
            
            # Crear copia del archivo (no mover, por seguridad)
            shutil.copy2(ruta_archivo, ruta_cuarentena)
            
            # Cambiar permisos para que no sea ejecutable
            os.chmod(ruta_cuarentena, 0o600)
            
            # Crear registro completo
            registro = {
                "id": hash_archivo[:16],
                "archivo_original": ruta_archivo,
                "archivo_cuarentena": ruta_cuarentena,
                "hash_sha256": hash_archivo,
                "timestamp_cuarentena": timestamp,
                "fecha_cuarentena": datetime.datetime.now().isoformat(),
                "motivo": motivo,
                "nivel_amenaza": nivel_amenaza,
                "fuente_deteccion": fuente_deteccion,
                "metadata": metadata,
                "estado": "ACTIVO",
                "acciones_realizadas": ["COPIADO_A_CUARENTENA", "PERMISOS_RESTRINGIDOS"]
            }
            
            # Intentar eliminar el archivo original (opcional)
            if self._es_seguro_eliminar(ruta_archivo):
                try:
                    # Sobrescribir el archivo original por seguridad antes de eliminarlo
                    self._sobrescribir_archivo_seguro(ruta_archivo)
                    os.remove(ruta_archivo)
                    registro["acciones_realizadas"].append("ARCHIVO_ORIGINAL_ELIMINADO")
                except Exception as e:
                    registro["acciones_realizadas"].append(f"ERROR_ELIMINANDO_ORIGINAL: {str(e)}")
            
            self.archivos_cuarentena.append(registro)
            self._guardar_registro()
            
            return {"exito": True, "registro": registro, "id": registro["id"]}
            
        except Exception as e:
            return {"exito": False, "error": f"Error en cuarentena: {str(e)}"}
    
    def _es_seguro_eliminar(self, ruta_archivo: str) -> bool:
        # No eliminar archivos del sistema críticos
        rutas_criticas = [
            '/bin/', '/sbin/', '/usr/bin/', '/usr/sbin/',
            '/etc/', '/boot/', '/sys/', '/proc/', '/dev/'
        ]
        
        ruta_absoluta = os.path.abspath(ruta_archivo)
        return not any(ruta_absoluta.startswith(ruta) for ruta in rutas_criticas)
    
    def _sobrescribir_archivo_seguro(self, ruta_archivo: str):
        try:
            tamaño = os.path.getsize(ruta_archivo)
            with open(ruta_archivo, 'wb') as f:
                # Sobrescribir con ceros
                f.write(b'\x00' * tamaño)
                f.flush()
                os.fsync(f.fileno())
        except:
            pass
    
    def aislar_proceso(self, pid: int, motivo: str = "Proceso sospechoso") -> Dict[str, Any]:
        if not self.es_kali:
            return {"exito": False, "error": "Aislamiento de procesos solo disponible en Linux"}
        
        try:
            # Verificar que el proceso existe
            if not os.path.exists(f"/proc/{pid}"):
                return {"exito": False, "error": "Proceso no existe"}
            
            # Obtener información del proceso
            info_proceso = self._obtener_info_proceso(pid)
            
            # Intentar suspender el proceso
            try:
                if platform.system() == "Linux":
                    os.kill(pid, 19)  # SIGSTOP
                    estado_suspension = "SUSPENDIDO"
                else:
                    return {"exito": False, "error": "Suspensión solo disponible en Linux"}
            except ProcessLookupError:
                return {"exito": False, "error": "Proceso ya no existe"}
            except PermissionError:
                return {"exito": False, "error": "Sin permisos para suspender el proceso"}
            
            # Registrar proceso aislado
            timestamp = datetime.datetime.now().isoformat()
            registro_proceso = {
                "pid": pid,
                "timestamp_aislamiento": timestamp,
                "motivo": motivo,
                "info_proceso": info_proceso,
                "estado": estado_suspension,
                "acciones": ["PROCESO_SUSPENDIDO"]
            }
            
            self.procesos_monitoreados[pid] = registro_proceso
            
            return {"exito": True, "registro": registro_proceso}
            
        except Exception as e:
            return {"exito": False, "error": f"Error aislando proceso: {str(e)}"}
    
    def _obtener_info_proceso(self, pid: int) -> Dict[str, Any]:
        try:
            # Leer información del proceso desde /proc
            with open(f"/proc/{pid}/cmdline", 'r') as f:
                cmdline = f.read().replace('\x00', ' ').strip()
            
            with open(f"/proc/{pid}/status", 'r') as f:
                status_lines = f.readlines()
            
            info = {"cmdline": cmdline}
            
            for line in status_lines:
                if line.startswith("Name:"):
                    info["nombre"] = line.split("\t")[1].strip()
                elif line.startswith("PPid:"):
                    info["ppid"] = line.split("\t")[1].strip()
                elif line.startswith("Uid:"):
                    info["uid"] = line.split("\t")[1].strip()
                elif line.startswith("VmSize:"):
                    info["memoria_virtual"] = line.split("\t")[1].strip()
            
            return info
            
        except Exception as e:
            return {"error": str(e)}
    
    def restaurar_de_cuarentena(self, archivo_id: str, forzar: bool = False) -> Dict[str, Any]:
        registro = self._buscar_registro_por_id(archivo_id)
        if not registro:
            return {"exito": False, "error": "Archivo no encontrado en cuarentena"}
        
        try:
            archivo_cuarentena = registro["archivo_cuarentena"]
            archivo_original = registro["archivo_original"]
            
            if not os.path.exists(archivo_cuarentena):
                return {"exito": False, "error": "Archivo no encontrado en cuarentena"}
            
            # Verificar si es seguro restaurar
            if not forzar and registro["nivel_amenaza"] in ["ALTO", "CRITICO"]:
                return {"exito": False, "error": "Archivo de alto riesgo. Use forzar=True para restaurar"}
            
            # Crear directorio de destino si no existe
            directorio_destino = os.path.dirname(archivo_original)
            if not os.path.exists(directorio_destino):
                os.makedirs(directorio_destino, exist_ok=True)
            
            # Verificar si el archivo original ya existe
            if os.path.exists(archivo_original):
                backup_name = f"{archivo_original}.backup_{int(time.time())}"
                shutil.move(archivo_original, backup_name)
            
            # Restaurar archivo
            shutil.copy2(archivo_cuarentena, archivo_original)
            
            # Actualizar registro
            registro["estado"] = "RESTAURADO"
            registro["timestamp_restauracion"] = datetime.datetime.now().isoformat()
            registro["acciones_realizadas"].append("ARCHIVO_RESTAURADO")
            
            self._guardar_registro()
            
            return {"exito": True, "archivo": archivo_original, "registro": registro}
            
        except Exception as e:
            return {"exito": False, "error": f"Error restaurando archivo: {str(e)}"}
    
    def eliminar_de_cuarentena(self, archivo_id: str) -> Dict[str, Any]:
        registro = self._buscar_registro_por_id(archivo_id)
        if not registro:
            return {"exito": False, "error": "Archivo no encontrado en cuarentena"}
        
        try:
            archivo_cuarentena = registro["archivo_cuarentena"]
            
            if os.path.exists(archivo_cuarentena):
                # Sobrescribir de forma segura antes de eliminar
                self._sobrescribir_archivo_seguro(archivo_cuarentena)
                os.remove(archivo_cuarentena)
            
            # Eliminar registro
            self.archivos_cuarentena = [r for r in self.archivos_cuarentena if r["id"] != archivo_id]
            self._guardar_registro()
            
            return {"exito": True, "mensaje": "Archivo eliminado permanentemente"}
            
        except Exception as e:
            return {"exito": False, "error": f"Error eliminando archivo: {str(e)}"}
    
    def reanudar_proceso(self, pid: int) -> Dict[str, Any]:
        if pid not in self.procesos_monitoreados:
            return {"exito": False, "error": "Proceso no está bajo monitoreo"}
        
        try:
            os.kill(pid, 18)  # SIGCONT
            
            # Actualizar registro
            self.procesos_monitoreados[pid]["estado"] = "REANUDADO"
            self.procesos_monitoreados[pid]["timestamp_reanudacion"] = datetime.datetime.now().isoformat()
            self.procesos_monitoreados[pid]["acciones"].append("PROCESO_REANUDADO")
            
            return {"exito": True, "mensaje": "Proceso reanudado"}
            
        except ProcessLookupError:
            return {"exito": False, "error": "Proceso ya no existe"}
        except Exception as e:
            return {"exito": False, "error": f"Error reanudando proceso: {str(e)}"}
    
    def terminar_proceso(self, pid: int, forzar: bool = False) -> Dict[str, Any]:
        if pid not in self.procesos_monitoreados:
            return {"exito": False, "error": "Proceso no está bajo monitoreo"}
        
        try:
            signal_usado = 9 if forzar else 15  # SIGKILL : SIGTERM
            os.kill(pid, signal_usado)
            
            # Actualizar registro
            self.procesos_monitoreados[pid]["estado"] = "TERMINADO"
            self.procesos_monitoreados[pid]["timestamp_terminacion"] = datetime.datetime.now().isoformat()
            self.procesos_monitoreados[pid]["acciones"].append(f"PROCESO_TERMINADO_{'FORZADO' if forzar else 'NORMAL'}")
            
            return {"exito": True, "mensaje": "Proceso terminado"}
            
        except ProcessLookupError:
            return {"exito": False, "error": "Proceso ya no existe"}
        except Exception as e:
            return {"exito": False, "error": f"Error terminando proceso: {str(e)}"}
    
    def _buscar_registro_por_id(self, archivo_id: str) -> Optional[Dict[str, Any]]:
        for registro in self.archivos_cuarentena:
            if registro["id"] == archivo_id:
                return registro
        return None
    
    def listar_cuarentena(self, filtro_estado: Optional[str] = None) -> List[Dict[str, Any]]:
        if filtro_estado:
            return [r for r in self.archivos_cuarentena if r.get("estado") == filtro_estado]
        return self.archivos_cuarentena.copy()
    
    def listar_procesos_monitoreados(self) -> Dict[int, Dict[str, Any]]:
        return self.procesos_monitoreados.copy()
    
    def obtener_estadisticas(self) -> Dict[str, Any]:
        estadisticas = {
            "total_archivos": len(self.archivos_cuarentena),
            "archivos_activos": len([r for r in self.archivos_cuarentena if r.get("estado") == "ACTIVO"]),
            "archivos_restaurados": len([r for r in self.archivos_cuarentena if r.get("estado") == "RESTAURADO"]),
            "procesos_monitoreados": len(self.procesos_monitoreados),
            "procesos_suspendidos": len([p for p in self.procesos_monitoreados.values() if p.get("estado") == "SUSPENDIDO"]),
            "espacio_usado_mb": self._calcular_espacio_usado(),
            "directorio_cuarentena": self.directorio_cuarentena,
            "sistema_activo": self.directorio_cuarentena is not None
        }
        
        # Estadísticas por nivel de amenaza
        niveles_amenaza = {}
        for registro in self.archivos_cuarentena:
            nivel = registro.get("nivel_amenaza", "DESCONOCIDO")
            niveles_amenaza[nivel] = niveles_amenaza.get(nivel, 0) + 1
        
        estadisticas["niveles_amenaza"] = niveles_amenaza
        
        return estadisticas
    
    def _calcular_espacio_usado(self) -> int:
        espacio_total = 0
        if not self.directorio_cuarentena:
            return 0
        
        try:
            for archivo in os.listdir(self.directorio_cuarentena):
                ruta_archivo = os.path.join(self.directorio_cuarentena, archivo)
                if os.path.isfile(ruta_archivo):
                    espacio_total += os.path.getsize(ruta_archivo)
            
            return espacio_total // (1024 * 1024)  # Convertir a MB
        except:
            return 0
    
    def limpiar_cuarentena_completa(self, confirmar: bool = False) -> Dict[str, Any]:
        if not confirmar:
            return {"exito": False, "error": "Operación requiere confirmación explícita"}
        
        eliminados = 0
        errores = []
        espacio_liberado = self._calcular_espacio_usado()
        
        # Eliminar archivos de cuarentena
        for registro in self.archivos_cuarentena.copy():
            try:
                archivo_cuarentena = registro["archivo_cuarentena"]
                if os.path.exists(archivo_cuarentena):
                    self._sobrescribir_archivo_seguro(archivo_cuarentena)
                    os.remove(archivo_cuarentena)
                eliminados += 1
            except Exception as e:
                errores.append(f"Error eliminando {registro['archivo_cuarentena']}: {e}")
        
        # Terminar procesos monitoreados
        procesos_terminados = 0
        for pid in list(self.procesos_monitoreados.keys()):
            try:
                if os.path.exists(f"/proc/{pid}"):
                    os.kill(pid, 15)  # SIGTERM
                    procesos_terminados += 1
            except:
                pass
        
        # Limpiar registros
        self.archivos_cuarentena.clear()
        self.procesos_monitoreados.clear()
        self._guardar_registro()
        
        return {
            "archivos_eliminados": eliminados,
            "procesos_terminados": procesos_terminados,
            "espacio_liberado_mb": espacio_liberado,
            "errores": errores,
            "mensaje": "Cuarentena completamente limpiada"
        }

# RESUMEN: Sistema de cuarentena avanzado para aislar archivos y procesos maliciosos con metadata completa,
# aislamiento de procesos, sobrescritura segura y gestión de amenazas por niveles en Kali Linux.