# -*- coding: utf-8 -*-

import os
import json
import datetime
import shutil
from typing import Dict, List, Any, Optional

class ModeloGestorDiccionarios:
    def __init__(self):
        self.directorio_diccionarios = self._crear_directorio_diccionarios()
        self.diccionarios_predefinidos = self._obtener_diccionarios_predefinidos()
        self._inicializar_diccionarios_basicos()
        self._cargar_diccionarios_desde_data()
    
    def _cargar_diccionarios_desde_data(self):
        """Carga automáticamente TODOS los diccionarios JSON desde el directorio data/diccionarios"""
        directorio_data = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "diccionarios")
        
        if not os.path.exists(directorio_data):
            print(f"📁 Directorio data/diccionarios no encontrado: {directorio_data}")
            return
        
        print(f"📂 Escaneando diccionarios en: {directorio_data}")
        
        # Detectar automáticamente todos los archivos JSON
        try:
            archivos_en_directorio = os.listdir(directorio_data)
            archivos_json = [f for f in archivos_en_directorio if f.endswith('.json')]
            
            if not archivos_json:
                print("📄 No se encontraron archivos JSON en data/diccionarios")
                return
            
            print(f"🔍 Encontrados {len(archivos_json)} archivos JSON")
            
        except Exception as e:
            print(f"❌ Error listando directorio: {e}")
            return
        
        diccionarios_cargados = 0
        
        for archivo in archivos_json:
            ruta_archivo = os.path.join(directorio_data, archivo)
            
            try:
                with open(ruta_archivo, 'r', encoding='utf-8') as f:
                    datos = json.load(f)
                
                # Procesar el archivo JSON
                nombre_diccionario = os.path.splitext(archivo)[0]
                resultado = self._procesar_diccionario_json(nombre_diccionario, datos, archivo)
                
                if resultado:
                    diccionarios_cargados += 1
                    
            except Exception as e:
                print(f"❌ Error cargando {archivo}: {e}")
        
        print(f"✅ {diccionarios_cargados} diccionarios cargados exitosamente")
        
        # Crear índice actualizado
        self._crear_indice_diccionarios()
    
    def _procesar_diccionario_json(self, nombre: str, datos: Any, archivo_origen: str) -> bool:
        """Procesa un archivo JSON y lo integra en los diccionarios"""
        try:
            print(f"📋 Procesando: {archivo_origen}")
            
            if isinstance(datos, dict):
                # Caso 1: Diccionario con múltiples categorías
                if all(isinstance(v, (list, dict)) for v in datos.values()):
                    for categoria, contenido in datos.items():
                        nombre_categoria = f"{nombre}_{categoria}"
                        
                        if isinstance(contenido, list):
                            self.diccionarios_predefinidos[nombre_categoria] = {
                                'tipo': 'lista',
                                'descripcion': f'Lista de {categoria} desde {archivo_origen}',
                                'datos': contenido,
                                'origen': archivo_origen
                            }
                            print(f"   ✓ Lista '{categoria}': {len(contenido)} elementos")
                        
                        elif isinstance(contenido, dict):
                            self.diccionarios_predefinidos[nombre_categoria] = {
                                'tipo': 'diccionario',
                                'descripcion': f'Diccionario de {categoria} desde {archivo_origen}',
                                'datos': contenido,
                                'origen': archivo_origen
                            }
                            print(f"   ✓ Diccionario '{categoria}': {len(contenido)} claves")
                
                # Caso 2: Diccionario simple
                else:
                    self.diccionarios_predefinidos[nombre] = {
                        'tipo': 'diccionario',
                        'descripcion': f'Diccionario desde {archivo_origen}',
                        'datos': datos,
                        'origen': archivo_origen
                    }
                    print(f"   ✓ Diccionario '{nombre}': {len(datos)} claves")
            
            elif isinstance(datos, list):
                # Caso 3: Lista directa
                self.diccionarios_predefinidos[nombre] = {
                    'tipo': 'lista',
                    'descripcion': f'Lista desde {archivo_origen}',
                    'datos': datos,
                    'origen': archivo_origen
                }
                print(f"   ✓ Lista '{nombre}': {len(datos)} elementos")
            
            else:
                print(f"   ⚠️ Formato no reconocido en {archivo_origen}")
                return False
            
            return True
            
        except Exception as e:
            print(f"❌ Error procesando {archivo_origen}: {e}")
            return False
    
    def _crear_directorio_diccionarios(self) -> str:
        # Primero intentar usar el directorio data del proyecto
        directorio_proyecto = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "data", "diccionarios")
        if os.path.exists(os.path.dirname(directorio_proyecto)):
            os.makedirs(directorio_proyecto, exist_ok=True)
            return directorio_proyecto
        
        # Si no existe, crear en home del usuario
        directorio = os.path.join(os.path.expanduser("~"), "aresitos_diccionarios")
        try:
            os.makedirs(directorio, exist_ok=True)
            return directorio
        except Exception:
            import tempfile
            directorio = os.path.join(tempfile.gettempdir(), "aresitos_diccionarios")
            os.makedirs(directorio, exist_ok=True)
            return directorio
    
    def _obtener_diccionarios_predefinidos(self) -> Dict[str, Any]:
        return {
            "vulnerabilidades_comunes": {
                "SQL_INJECTION": "Inyección de código SQL malicioso en aplicaciones web",
                "XSS": "Cross-Site Scripting - Ejecución de scripts maliciosos en navegadores",
                "CSRF": "Cross-Site Request Forgery - Ejecución de acciones no autorizadas",
                "DIRECTORY_TRAVERSAL": "Acceso a archivos fuera del directorio web permitido",
                "BUFFER_OVERFLOW": "Desbordamiento de buffer que puede permitir ejecución de código",
                "PRIVILEGE_ESCALATION": "Escalada de privilegios para obtener acceso administrativo",
                "WEAK_AUTHENTICATION": "Mecanismos de autenticación débiles o mal configurados",
                "INSECURE_STORAGE": "Almacenamiento inseguro de datos sensibles",
                "BROKEN_ACCESS_CONTROL": "Control de acceso roto o mal implementado",
                "SECURITY_MISCONFIGURATION": "Configuración de seguridad incorrecta o por defecto"
            },
            "herramientas_ciberseguridad": {
                "NMAP": "Escáner de puertos y discovery de red para auditorías de seguridad",
                "METASPLOIT": "Framework de explotación para pruebas de penetración",
                "BURP_SUITE": "Plataforma integrada para testing de seguridad en aplicaciones web",
                "WIRESHARK": "Analizador de protocolos de red para captura y análisis de tráfico",
                "JOHN_THE_RIPPER": "Herramienta de cracking de contraseñas",
                "HASHCAT": "Herramienta avanzada de recuperación de contraseñas",
                "AIRCRACK_NG": "Suite de herramientas para auditoría de redes inalámbricas",
                "SQLMAP": "Herramienta automática para detección y explotación de SQL injection",
                "HYDRA": "Herramienta de fuerza bruta para login paralelo",
                "LYNIS": "Herramienta de auditoría y hardening de sistemas Unix/Linux"
            },
            "tipos_ataques": {
                "PHISHING": "Suplantación de identidad para robar credenciales",
                "MALWARE": "Software malicioso diseñado para dañar sistemas",
                "RANSOMWARE": "Malware que cifra archivos y exige rescate",
                "DDoS": "Ataque distribuido de denegación de servicio",
                "MAN_IN_THE_MIDDLE": "Interceptación de comunicaciones entre dos partes",
                "SOCIAL_ENGINEERING": "Manipulación psicológica para obtener información",
                "BRUTE_FORCE": "Ataque por fuerza bruta para descifrar contraseñas",
                "ZERO_DAY": "Explotación de vulnerabilidades no conocidas públicamente",
                "APT": "Amenaza persistente avanzada - ataque dirigido y prolongado",
                "INSIDER_THREAT": "Amenaza interna de empleados o personal con acceso"
            },
            "protocolos_red": {
                "HTTP": "Protocolo de transferencia de hipertexto para navegación web",
                "HTTPS": "HTTP seguro con cifrado SSL/TLS",
                "FTP": "Protocolo de transferencia de archivos",
                "SSH": "Secure Shell para acceso remoto seguro",
                "TELNET": "Protocolo de acceso remoto sin cifrado (inseguro)",
                "SMTP": "Protocolo simple de transferencia de correo",
                "POP3": "Protocolo de oficina postal versión 3",
                "IMAP": "Protocolo de acceso a mensajes de Internet",
                "DNS": "Sistema de nombres de dominio",
                "DHCP": "Protocolo de configuración dinámica de host"
            },
            "puertos_comunes": {
                "21": "FTP - File Transfer Protocol",
                "22": "SSH - Secure Shell",
                "23": "Telnet - Terminal Network",
                "25": "SMTP - Simple Mail Transfer Protocol",
                "53": "DNS - Domain Name System",
                "80": "HTTP - HyperText Transfer Protocol",
                "110": "POP3 - Post Office Protocol",
                "143": "IMAP - Internet Message Access Protocol",
                "443": "HTTPS - HTTP Secure",
                "993": "IMAPS - IMAP Secure",
                "995": "POP3S - POP3 Secure",
                "3389": "RDP - Remote Desktop Protocol",
                "5432": "PostgreSQL Database",
                "3306": "MySQL Database"
            }
        }
    
    def _inicializar_diccionarios_basicos(self):
        for nombre, contenido in self.diccionarios_predefinidos.items():
            ruta_archivo = os.path.join(self.directorio_diccionarios, f"{nombre}.json")
            if not os.path.exists(ruta_archivo):
                try:
                    with open(ruta_archivo, 'w', encoding='utf-8') as f:
                        json.dump(contenido, f, indent=2, ensure_ascii=False)
                except Exception:
                    pass
    
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
                            contenido = json.load(f)
                            entradas = len(contenido) if isinstance(contenido, dict) else 0
                    except:
                        entradas = 0
                    
                    diccionarios.append({
                        'nombre': archivo[:-5],  # Quitar .json
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
            
            # Verificar que es un JSON válido
            with open(ruta_origen, 'r', encoding='utf-8') as f:
                contenido = json.load(f)
            
            shutil.copy2(ruta_origen, ruta_destino)
            
            return {
                'exito': True,
                'archivo': nombre_destino,
                'ruta': ruta_destino,
                'entradas': len(contenido) if isinstance(contenido, dict) else 0
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
            
        except json.JSONDecodeError:
            return {'exito': False, 'error': 'Error al leer JSON'}
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def guardar_diccionario(self, nombre: str, contenido: Dict[str, Any]) -> Dict[str, Any]:
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
                'entradas': len(contenido) if isinstance(contenido, dict) else 0
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
                        termino_lower in str(valor).lower()):
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
                # Si no existe, crear diccionario nuevo
                contenido = {}
            else:
                contenido = resultado['contenido']
                if not isinstance(contenido, dict):
                    return {'exito': False, 'error': 'El diccionario no tiene formato válido'}
            
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
                return {'exito': False, 'error': 'El diccionario no tiene formato válido'}
            
            if clave not in contenido:
                return {'exito': False, 'error': 'Clave no encontrada'}
            
            del contenido[clave]
            
            return self.guardar_diccionario(nombre, contenido)
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def importar_desde_texto(self, nombre: str, ruta_archivo: str, separador: str = ':') -> Dict[str, Any]:
        try:
            contenido = {}
            
            with open(ruta_archivo, 'r', encoding='utf-8') as f:
                for linea in f:
                    linea = linea.strip()
                    if linea and separador in linea:
                        partes = linea.split(separador, 1)
                        if len(partes) == 2:
                            clave = partes[0].strip()
                            valor = partes[1].strip()
                            contenido[clave] = valor
            
            return self.guardar_diccionario(nombre, contenido)
            
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def obtener_estadisticas(self, nombre: str) -> Dict[str, Any]:
        try:
            resultado = self.obtener_contenido_diccionario(nombre)
            if not resultado['exito']:
                return resultado
            
            contenido = resultado['contenido']
            
            if isinstance(contenido, dict):
                estadisticas = {
                    'total_entradas': len(contenido),
                    'claves_mas_largas': [],
                    'valores_mas_largos': [],
                    'promedio_longitud_clave': 0,
                    'promedio_longitud_valor': 0
                }
                
                if contenido:
                    longitudes_claves = [len(k) for k in contenido.keys()]
                    longitudes_valores = [len(str(v)) for v in contenido.values()]
                    
                    estadisticas['promedio_longitud_clave'] = sum(longitudes_claves) / len(longitudes_claves)
                    estadisticas['promedio_longitud_valor'] = sum(longitudes_valores) / len(longitudes_valores)
                    
                    # Top 5 claves más largas
                    claves_ordenadas = sorted(contenido.keys(), key=len, reverse=True)[:5]
                    estadisticas['claves_mas_largas'] = claves_ordenadas
                    
                    # Top 5 valores más largos
                    valores_ordenados = sorted(contenido.items(), key=lambda x: len(str(x[1])), reverse=True)[:5]
                    estadisticas['valores_mas_largos'] = [{'clave': k, 'valor': v} for k, v in valores_ordenados]
                
                return {
                    'exito': True,
                    'estadisticas': estadisticas
                }
            else:
                return {'exito': False, 'error': 'Formato de diccionario no válido'}
                
        except Exception as e:
            return {'exito': False, 'error': str(e)}
    
    def _crear_indice_diccionarios(self):
        """Crea un archivo de índice con todos los diccionarios disponibles"""
        try:
            indice_path = os.path.join(self.directorio_diccionarios, "INDICE_DICCIONARIOS_CARGADOS.md")
            
            with open(indice_path, 'w', encoding='utf-8') as f:
                f.write("# Índice de Diccionarios Cargados - Aresitos\n\n")
                f.write(f"**Generado el:** {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                f.write(f"**Total de categorías:** {len(self.diccionarios_predefinidos)}\n\n")
                
                for categoria, diccionario in self.diccionarios_predefinidos.items():
                    f.write(f"## {categoria}\n")
                    f.write(f"- **Entradas:** {len(diccionario)}\n")
                    if len(diccionario) > 0:
                        ejemplos = list(diccionario.keys())[:3]
                        f.write(f"- **Ejemplos:** {', '.join(ejemplos)}\n")
                    f.write("\n")
                
                f.write("---\n")
                f.write("*Índice generado automáticamente por Aresitos*\n")
            
            print(f"📄 Índice de diccionarios creado: {indice_path}")
            
        except Exception as e:
            print(f"❌ Error creando índice de diccionarios: {e}")

# RESUMEN: Gestor completo de diccionarios de ciberseguridad que maneja almacenamiento JSON,
# incluye diccionarios predefinidos (vulnerabilidades, herramientas, ataques, protocolos, puertos),
# proporciona CRUD completo y funciones avanzadas como búsqueda, estadísticas e importación.
# Ahora con carga automática desde data/diccionarios del proyecto.
