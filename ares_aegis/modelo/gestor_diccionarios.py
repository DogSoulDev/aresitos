# -*- coding: utf-8 -*-

import os
import json
import datetime
import shutil
from typing import List, Dict, Optional, Any

class GestorDiccionarios:
    
    def __init__(self):
        self.directorio_diccionarios = self._crear_directorio_diccionarios()
        self.diccionarios_predefinidos = self._obtener_diccionarios_predefinidos()
        self._inicializar_diccionarios_basicos()
    
    def _crear_directorio_diccionarios(self) -> str:
        directorio = os.path.join(os.path.expanduser("~"), "aresitos_diccionarios")
        try:
            os.makedirs(directorio, exist_ok=True)
            return directorio
        except Exception:
            import tempfile
            directorio = os.path.join(tempfile.gettempdir(), "aresitos_diccionarios")
            os.makedirs(directorio, exist_ok=True)
            return directorio
    
    def _obtener_diccionarios_predefinidos(self) -> Dict[str, Dict[str, str]]:
        return {
            "puertos_comunes": {
                "21": "FTP - File Transfer Protocol",
                "22": "SSH - Secure Shell",
                "23": "Telnet",
                "25": "SMTP - Simple Mail Transfer Protocol",
                "53": "DNS - Domain Name System",
                "80": "HTTP - HyperText Transfer Protocol",
                "110": "POP3 - Post Office Protocol v3",
                "143": "IMAP - Internet Message Access Protocol",
                "443": "HTTPS - HTTP Secure",
                "993": "IMAPS - IMAP Secure",
                "995": "POP3S - POP3 Secure",
                "3389": "RDP - Remote Desktop Protocol",
                "5432": "PostgreSQL Database",
                "3306": "MySQL Database",
                "1433": "Microsoft SQL Server",
                "27017": "MongoDB",
                "6379": "Redis",
                "8080": "HTTP Alternate",
                "8443": "HTTPS Alternate",
                "9200": "Elasticsearch"
            },
            "vulnerabilidades_comunes": {
                "SQLi": "SQL Injection - Inyección de código SQL",
                "XSS": "Cross-Site Scripting - Secuencias de comandos en sitios cruzados",
                "CSRF": "Cross-Site Request Forgery - Falsificación de petición en sitios cruzados",
                "LFI": "Local File Inclusion - Inclusión de archivos locales",
                "RFI": "Remote File Inclusion - Inclusión de archivos remotos",
                "XXE": "XML External Entity - Entidad externa XML",
                "SSRF": "Server-Side Request Forgery - Falsificación de solicitudes del lado del servidor",
                "RCE": "Remote Code Execution - Ejecución remota de código",
                "IDOR": "Insecure Direct Object References - Referencias directas a objetos inseguras",
                "LPE": "Local Privilege Escalation - Escalación local de privilegios",
                "BOF": "Buffer Overflow - Desbordamiento de búfer",
                "LDAP": "LDAP Injection - Inyección LDAP",
                "XPATH": "XPath Injection - Inyección XPath",
                "SSTI": "Server-Side Template Injection - Inyección de plantillas del lado del servidor"
            },
            "herramientas_hacking": {
                "nmap": "Network Mapper - Escáner de puertos y servicios",
                "nessus": "Escáner de vulnerabilidades",
                "burp": "Burp Suite - Plataforma de pruebas de aplicaciones web",
                "metasploit": "Framework de explotación",
                "wireshark": "Analizador de protocolos de red",
                "sqlmap": "Herramienta de inyección SQL automática",
                "nikto": "Escáner de vulnerabilidades web",
                "dirb": "Escáner de directorios web",
                "gobuster": "Herramienta de fuzzing de directorios/archivos",
                "hydra": "Herramienta de fuerza bruta",
                "john": "John the Ripper - Crackeador de contraseñas",
                "hashcat": "Crackeador de hashes avanzado",
                "aircrack": "Suite de herramientas para auditoría Wi-Fi",
                "maltego": "Herramienta de inteligencia y análisis forense"
            },
            "tipos_malware": {
                "virus": "Código malicioso que se replica adjuntándose a otros programas",
                "worm": "Malware que se propaga automáticamente a través de redes",
                "trojan": "Programa que aparenta ser útil pero contiene código malicioso",
                "ransomware": "Malware que cifra archivos y exige rescate",
                "spyware": "Software que recopila información sin consentimiento",
                "adware": "Software que muestra publicidad no deseada",
                "rootkit": "Conjunto de herramientas para ocultar actividad maliciosa",
                "botnet": "Red de computadoras infectadas controladas remotamente",
                "keylogger": "Software que registra pulsaciones de teclado",
                "backdoor": "Acceso secreto a un sistema",
                "dropper": "Programa que instala otros malware",
                "apt": "Advanced Persistent Threat - Amenaza persistente avanzada"
            },
            "terminos_forense": {
                "hash": "Función criptográfica que produce un valor único para datos",
                "timeline": "Línea de tiempo de eventos en un sistema",
                "artifact": "Evidencia digital dejada por actividad en el sistema",
                "imaging": "Proceso de crear copia exacta de un dispositivo",
                "carving": "Recuperación de archivos sin metadatos del sistema de archivos",
                "volatility": "Análisis de memoria volátil (RAM)",
                "steganography": "Técnica de ocultar información en otros medios",
                "chain_custody": "Cadena de custodia de evidencia digital",
                "write_blocker": "Dispositivo que previene escritura en evidencia",
                "slack_space": "Espacio no utilizado en clusters del disco",
                "unallocated": "Espacio del disco no asignado a archivos",
                "metadata": "Datos sobre datos, información adicional de archivos"
            }
        }
    
    def _inicializar_diccionarios_basicos(self):
        for nombre, diccionario in self.diccionarios_predefinidos.items():
            ruta_archivo = os.path.join(self.directorio_diccionarios, f"{nombre}.json")
            if not os.path.exists(ruta_archivo):
                try:
                    with open(ruta_archivo, 'w', encoding='utf-8') as f:
                        json.dump(diccionario, f, indent=2, ensure_ascii=False)
                except Exception:
                    pass  # Ignorar errores en inicialización
    
    def listar_diccionarios(self) -> List[Dict[str, Any]]:
        diccionarios = []
        
        if not os.path.exists(self.directorio_diccionarios):
            return diccionarios
        
        try:
            for archivo in os.listdir(self.directorio_diccionarios):
                if archivo.endswith('.json'):
                    ruta_completa = os.path.join(self.directorio_diccionarios, archivo)
                    stat_info = os.stat(ruta_completa)
                    
                    try:
                        with open(ruta_completa, 'r', encoding='utf-8') as f:
                            data = json.load(f)
                            entradas = len(data) if isinstance(data, dict) else 0
                    except:
                        entradas = 0
                    
                    diccionarios.append({
                        'nombre': archivo[:-5],  # Sin extensión .json
                        'archivo': archivo,
                        'ruta': ruta_completa,
                        'tamaño': stat_info.st_size,
                        'entradas': entradas,
                        'modificado': datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime("%Y-%m-%d %H:%M:%S")
                    })
        except Exception:
            pass
        
        return sorted(diccionarios, key=lambda x: x['nombre'])
    
    def cargar_diccionario(self, ruta_origen: str, nombre_destino: Optional[str] = None) -> Dict[str, Any]:
        try:
            if not os.path.exists(ruta_origen):
                return {'exito': False, 'error': 'Archivo no encontrado'}
            
            if not nombre_destino:
                nombre_destino = os.path.splitext(os.path.basename(ruta_origen))[0]
            
            if not nombre_destino.endswith('.json'):
                nombre_destino += '.json'
            
            ruta_destino = os.path.join(self.directorio_diccionarios, nombre_destino)
            
            with open(ruta_origen, 'r', encoding='utf-8') as f:
                data = json.load(f)
            
            shutil.copy2(ruta_origen, ruta_destino)
            
            return {
                'exito': True,
                'archivo': nombre_destino,
                'ruta': ruta_destino,
                'entradas': len(data) if isinstance(data, dict) else 0
            }
            
        except json.JSONDecodeError:
            return {'exito': False, 'error': 'El archivo no es un JSON válido'}
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def obtener_contenido_diccionario(self, nombre: str) -> Dict[str, Any]:
        try:
            if not nombre.endswith('.json'):
                nombre += '.json'
            
            ruta_archivo = os.path.join(self.directorio_diccionarios, nombre)
            
            if not os.path.exists(ruta_archivo):
                return {'exito': False, 'error': 'Diccionario no encontrado'}
            
            with open(ruta_archivo, 'r', encoding='utf-8') as f:
                contenido = json.load(f)
            
            return {
                'exito': True,
                'contenido': contenido,
                'entradas': len(contenido) if isinstance(contenido, dict) else 0,
                'nombre': nombre
            }
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def guardar_diccionario(self, nombre: str, contenido: Dict[str, str]) -> Dict[str, Any]:
        try:
            if not nombre.endswith('.json'):
                nombre += '.json'
            
            ruta_archivo = os.path.join(self.directorio_diccionarios, nombre)
            
            with open(ruta_archivo, 'w', encoding='utf-8') as f:
                json.dump(contenido, f, indent=2, ensure_ascii=False)
            
            return {
                'exito': True,
                'archivo': nombre,
                'ruta': ruta_archivo,
                'entradas': len(contenido)
            }
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def eliminar_diccionario(self, nombre: str) -> Dict[str, Any]:
        try:
            if not nombre.endswith('.json'):
                nombre += '.json'
            
            ruta_archivo = os.path.join(self.directorio_diccionarios, nombre)
            
            if not os.path.exists(ruta_archivo):
                return {'exito': False, 'error': 'Diccionario no encontrado'}
            
            os.remove(ruta_archivo)
            
            return {'exito': True, 'mensaje': f'Diccionario {nombre} eliminado'}
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def exportar_diccionario_txt(self, nombre: str, ruta_destino: str) -> Dict[str, Any]:
        try:
            resultado = self.obtener_contenido_diccionario(nombre)
            if not resultado['exito']:
                return resultado
            
            contenido = resultado['contenido']
            
            with open(ruta_destino, 'w', encoding='utf-8') as f:
                if isinstance(contenido, dict):
                    for clave, valor in contenido.items():
                        f.write(f"{clave}: {valor}\n")
                else:
                    f.write(str(contenido))
            
            return {
                'exito': True,
                'archivo_exportado': ruta_destino
            }
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def buscar_en_diccionario(self, nombre: str, termino: str) -> Dict[str, Any]:
        try:
            resultado = self.obtener_contenido_diccionario(nombre)
            if not resultado['exito']:
                return resultado
            
            contenido = resultado['contenido']
            coincidencias = {}
            
            if isinstance(contenido, dict):
                termino_lower = termino.lower()
                for clave, valor in contenido.items():
                    if (termino_lower in clave.lower() or 
                        termino_lower in valor.lower()):
                        coincidencias[clave] = valor
            
            return {
                'exito': True,
                'coincidencias': coincidencias,
                'total': len(coincidencias)
            }
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def agregar_entrada(self, nombre: str, clave: str, valor: str) -> Dict[str, Any]:
        try:
            resultado = self.obtener_contenido_diccionario(nombre)
            if not resultado['exito']:
                return resultado
            
            contenido = resultado['contenido']
            if not isinstance(contenido, dict):
                return {'exito': False, 'error': 'El diccionario no tiene el formato correcto'}
            
            contenido[clave] = valor
            
            return self.guardar_diccionario(nombre, contenido)
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def eliminar_entrada(self, nombre: str, clave: str) -> Dict[str, Any]:
        try:
            resultado = self.obtener_contenido_diccionario(nombre)
            if not resultado['exito']:
                return resultado
            
            contenido = resultado['contenido']
            if not isinstance(contenido, dict):
                return {'exito': False, 'error': 'El diccionario no tiene el formato correcto'}
            
            if clave not in contenido:
                return {'exito': False, 'error': 'Entrada no encontrada'}
            
            del contenido[clave]
            
            return self.guardar_diccionario(nombre, contenido)
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}


# RESUMEN: Gestor de diccionarios técnicos con almacenamiento JSON y búsqueda.