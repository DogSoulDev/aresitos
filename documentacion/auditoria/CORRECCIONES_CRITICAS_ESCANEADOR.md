# 🔧 CORRECCIONES DE SEGURIDAD - ESCANEADOR PROFESIONAL v2.0
## Implementación de Parches de Seguridad Críticos

### 🎯 OBJETIVO
Implementar correcciones inmediatas para las 7 vulnerabilidades críticas identificadas en la auditoría de seguridad del escaneador profesional.

---

## 🚨 CORRECCIÓN CRÍTICA #1: Validación Universal de Inputs

### Archivo a modificar: `escaneador_kali_real.py`

#### Agregar al inicio de la clase EscaneadorKaliReal:

```python
import ipaddress
import re
from urllib.parse import urlparse

class EscaneadorKaliReal:
    def __init__(self, siem=None):
        # ... código existente ...
        
        # Configuración de seguridad mejorada
        self.config_seguridad = {
            'max_timeout': 300,  # Reducido de 3600 a 300 segundos
            'max_puertos_por_escaneo': 1000,  # Reducido de 65535
            'max_threads': 50,  # Reducido de 100
            'ips_prohibidas': {
                '0.0.0.0', '127.0.0.1', '::1', 'localhost',
                '169.254.0.0/16',  # Link-local
                '224.0.0.0/4',     # Multicast
                '240.0.0.0/4'      # Reserved
            },
            'comandos_permitidos': {
                'nmap', 'masscan', 'nikto', 'gobuster', 'whatweb', 
                'nuclei', 'clamav', 'clamscan', 'lynis', 'chkrootkit', 
                'rkhunter', 'ss', 'netstat', 'lsof', 'ps'
            },
            'patrones_seguros': {
                'ip_v4': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$',
                'ip_v6': r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$',
                'hostname': r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$',
                'cidr': r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/(?:[0-9]|[1-2][0-9]|3[0-2])$',
                'puerto': r'^(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$',
                'rango_puertos': r'^(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])-(?:[1-9][0-9]{0,3}|[1-5][0-9]{4}|6[0-4][0-9]{3}|65[0-4][0-9]{2}|655[0-2][0-9]|6553[0-5])$'
            }
        }
    
    def _validar_objetivo_seguro(self, objetivo: str) -> bool:
        """
        Validación estricta y segura de objetivos.
        
        Args:
            objetivo: IP, hostname o CIDR a validar
            
        Returns:
            bool: True si el objetivo es válido y seguro
            
        Raises:
            ValueError: Si el objetivo es inválido o inseguro
        """
        if not objetivo or not isinstance(objetivo, str):
            raise ValueError("Objetivo debe ser una cadena no vacía")
        
        objetivo = objetivo.strip()
        
        # Verificar longitud máxima
        if len(objetivo) > 253:  # RFC límite para hostnames
            raise ValueError("Objetivo excede longitud máxima permitida")
        
        # Verificar caracteres peligrosos
        caracteres_prohibidos = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", '\\']
        if any(char in objetivo for char in caracteres_prohibidos):
            raise ValueError("Objetivo contiene caracteres prohibidos")
        
        # Validar formato
        es_ip_v4 = re.match(self.config_seguridad['patrones_seguros']['ip_v4'], objetivo)
        es_ip_v6 = re.match(self.config_seguridad['patrones_seguros']['ip_v6'], objetivo)
        es_hostname = re.match(self.config_seguridad['patrones_seguros']['hostname'], objetivo)
        es_cidr = re.match(self.config_seguridad['patrones_seguros']['cidr'], objetivo)
        
        if not (es_ip_v4 or es_ip_v6 or es_hostname or es_cidr):
            raise ValueError("Formato de objetivo inválido")
        
        # Verificar IPs prohibidas
        try:
            if es_ip_v4 or es_ip_v6:
                ip = ipaddress.ip_address(objetivo)
                if str(ip) in self.config_seguridad['ips_prohibidas']:
                    raise ValueError("IP en lista de prohibidas")
                
                # Verificar rangos prohibidos
                if ip.is_private and not self._es_red_permitida(ip):
                    raise ValueError("Red privada no permitida")
                    
                if ip.is_loopback or ip.is_multicast or ip.is_reserved:
                    raise ValueError("Tipo de IP no permitida")
                    
        except ipaddress.AddressValueError:
            pass  # No es IP, continuar con validación de hostname
        
        # Verificar hostnames peligrosos
        hostnames_prohibidos = ['localhost', 'local', 'internal', 'admin', 'root']
        if any(prohibido in objetivo.lower() for prohibido in hostnames_prohibidos):
            raise ValueError("Hostname contiene términos prohibidos")
        
        self.logger.debug(f"Objetivo validado correctamente: {objetivo[:10]}...")
        return True
    
    def _es_red_permitida(self, ip: ipaddress.IPv4Address) -> bool:
        """Verificar si una IP privada está en redes permitidas."""
        redes_permitidas = [
            ipaddress.ip_network('192.168.0.0/16'),
            ipaddress.ip_network('10.0.0.0/8'),
            ipaddress.ip_network('172.16.0.0/12')
        ]
        return any(ip in red for red in redes_permitidas)
    
    def _validar_puertos_seguro(self, puertos: str) -> bool:
        """
        Validación segura de rangos de puertos.
        
        Args:
            puertos: String con puertos o rango (ej: "80", "80-443", "80,443")
            
        Returns:
            bool: True si los puertos son válidos
            
        Raises:
            ValueError: Si los puertos son inválidos
        """
        if not puertos or not isinstance(puertos, str):
            raise ValueError("Puertos debe ser una cadena no vacía")
        
        puertos = puertos.strip()
        
        # Verificar caracteres peligrosos
        if not re.match(r'^[0-9,-]+$', puertos):
            raise ValueError("Formato de puertos inválido")
        
        # Procesar diferentes formatos
        partes = puertos.split(',')
        total_puertos = 0
        
        for parte in partes:
            parte = parte.strip()
            
            if '-' in parte:
                # Rango de puertos
                if not re.match(self.config_seguridad['patrones_seguros']['rango_puertos'], parte):
                    raise ValueError(f"Rango de puertos inválido: {parte}")
                
                inicio, fin = map(int, parte.split('-'))
                if inicio > fin:
                    raise ValueError(f"Rango inválido: inicio ({inicio}) > fin ({fin})")
                
                total_puertos += (fin - inicio + 1)
            else:
                # Puerto individual
                if not re.match(self.config_seguridad['patrones_seguros']['puerto'], parte):
                    raise ValueError(f"Puerto inválido: {parte}")
                
                total_puertos += 1
        
        # Verificar límite de puertos
        if total_puertos > self.config_seguridad['max_puertos_por_escaneo']:
            raise ValueError(f"Demasiados puertos: {total_puertos} > {self.config_seguridad['max_puertos_por_escaneo']}")
        
        self.logger.debug(f"Puertos validados: {total_puertos} puertos")
        return True
```

---

## 🚨 CORRECCIÓN CRÍTICA #2: Sanitización de Comandos

### Archivo a modificar: `escaneador_kali_real.py`

#### Agregar método de sanitización:

```python
def _sanitizar_comando_seguro(self, herramienta: str, argumentos: List[str]) -> List[str]:
    """
    Sanitización estricta de comandos antes de ejecución.
    
    Args:
        herramienta: Nombre de la herramienta a ejecutar
        argumentos: Lista de argumentos para la herramienta
        
    Returns:
        List[str]: Comando sanitizado
        
    Raises:
        SecurityError: Si el comando es inseguro
    """
    # Verificar herramienta permitida
    if herramienta not in self.config_seguridad['comandos_permitidos']:
        raise SecurityError(f"Herramienta no permitida: {herramienta}")
    
    # Obtener ruta completa y verificar
    ruta_herramienta = self._verificar_herramienta_segura(herramienta)
    
    # Sanitizar argumentos
    argumentos_seguros = []
    for arg in argumentos:
        if not isinstance(arg, str):
            arg = str(arg)
        
        # Verificar caracteres peligrosos
        caracteres_prohibidos = [';', '&', '|', '`', '$', '(', ')', '<', '>', '"', "'", '\\', '\n', '\r']
        if any(char in arg for char in caracteres_prohibidos):
            raise SecurityError(f"Argumento contiene caracteres prohibidos: {arg}")
        
        # Escapar argumento
        arg_seguro = shlex.quote(arg)
        argumentos_seguros.append(arg_seguro)
    
    comando_final = [ruta_herramienta] + argumentos_seguros
    
    self.logger.info(f"Comando sanitizado: {herramienta} con {len(argumentos_seguros)} argumentos")
    return comando_final

def _verificar_herramienta_segura(self, herramienta: str) -> str:
    """
    Verificar que la herramienta está en ubicación segura.
    
    Args:
        herramienta: Nombre de la herramienta
        
    Returns:
        str: Ruta completa de la herramienta
        
    Raises:
        SecurityError: Si la herramienta no se encuentra en rutas seguras
    """
    rutas_seguras = ['/usr/bin/', '/usr/local/bin/', '/bin/', '/usr/sbin/', '/sbin/']
    
    for ruta in rutas_seguras:
        ruta_completa = os.path.join(ruta, herramienta)
        if os.path.isfile(ruta_completa) and os.access(ruta_completa, os.X_OK):
            # Verificar que no es un enlace simbólico malicioso
            if os.path.islink(ruta_completa):
                destino = os.readlink(ruta_completa)
                if not destino.startswith('/usr/') and not destino.startswith('/bin/'):
                    continue
            
            return ruta_completa
    
    raise SecurityError(f"Herramienta {herramienta} no encontrada en rutas seguras")

class SecurityError(Exception):
    """Excepción para errores de seguridad."""
    pass
```

---

## 🚨 CORRECCIÓN CRÍTICA #3: Logging Seguro

### Archivo a modificar: `escaneador_kali_real.py`

#### Reemplazar todos los logs de comandos:

```python
def _log_comando_seguro(self, herramienta: str, num_argumentos: int, objetivo_censurado: str = None):
    """
    Logging seguro de comandos sin exponer información sensible.
    
    Args:
        herramienta: Nombre de la herramienta
        num_argumentos: Número de argumentos
        objetivo_censurado: Objetivo censurado para logs
    """
    if objetivo_censurado:
        objetivo_log = self._censurar_objetivo(objetivo_censurado)
    else:
        objetivo_log = "[censurado]"
    
    self.logger.info(f"Ejecutando {herramienta} con {num_argumentos} argumentos, objetivo: {objetivo_log}")

def _censurar_objetivo(self, objetivo: str) -> str:
    """
    Censurar objetivo para logs seguros.
    
    Args:
        objetivo: Objetivo original
        
    Returns:
        str: Objetivo censurado
    """
    if not objetivo:
        return "[vacío]"
    
    # Para IPs, mostrar solo los primeros dos octetos
    if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$', objetivo):
        partes = objetivo.split('.')
        return f"{partes[0]}.{partes[1]}.xxx.xxx"
    
    # Para hostnames, mostrar solo el dominio principal
    if '.' in objetivo:
        partes = objetivo.split('.')
        if len(partes) >= 2:
            return f"xxx.{partes[-1]}"
    
    # Para otros casos, mostrar longitud
    return f"[objetivo_{len(objetivo)}_chars]"

def _auditar_operacion_critica(self, operacion: str, parametros: Dict[str, Any], resultado: str):
    """
    Auditar operaciones críticas de seguridad.
    
    Args:
        operacion: Tipo de operación
        parametros: Parámetros censurados
        resultado: Resultado de la operación
    """
    evento_auditoria = {
        'timestamp': datetime.datetime.now().isoformat(),
        'operacion': operacion,
        'usuario': getpass.getuser(),
        'pid': os.getpid(),
        'parametros_hash': hashlib.sha256(str(parametros).encode()).hexdigest(),
        'exito': 'exito' in resultado.lower(),
        'ip_origen': self._obtener_ip_local(),
        'session_id': self._obtener_session_id()
    }
    
    # Escribir a log de auditoría separado
    self._escribir_auditoria(evento_auditoria)

def _escribir_auditoria(self, evento: Dict[str, Any]):
    """Escribir evento de auditoría a archivo seguro."""
    try:
        log_path = "/var/log/ares_aegis/auditoria.log"
        os.makedirs(os.path.dirname(log_path), exist_ok=True)
        
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(json.dumps(evento) + '\n')
            
        # Establecer permisos seguros (solo root y ares_aegis pueden leer)
        os.chmod(log_path, 0o640)
    except Exception as e:
        self.logger.error(f"Error escribiendo auditoría: {e}")
```

---

## 🚨 CORRECCIÓN CRÍTICA #4: Timeouts y Rate Limiting

### Archivo a modificar: `escaneador_kali_real.py`

#### Agregar sistema de rate limiting:

```python
import time
from collections import defaultdict, deque

class EscaneadorKaliReal:
    def __init__(self, siem=None):
        # ... código existente ...
        
        # Sistema de rate limiting
        self.rate_limits = defaultdict(deque)
        self.operaciones_activas = {}
        self.max_operaciones_simultaneas = 3
        
        # Límites por tipo de operación (operaciones por hora)
        self.limites_operacion = {
            'escaneo_completo': 10,
            'escaneo_vulnerabilidades': 20,
            'deteccion_malware': 5,
            'auditoria_sistema': 3
        }
    
    def _verificar_rate_limit(self, operacion: str) -> bool:
        """
        Verificar límites de operaciones por tiempo.
        
        Args:
            operacion: Tipo de operación
            
        Returns:
            bool: True si está dentro del límite
            
        Raises:
            SecurityError: Si se excede el rate limit
        """
        ahora = time.time()
        usuario = getpass.getuser()
        key = f"{operacion}_{usuario}"
        
        # Limpiar entradas antiguas (última hora)
        while self.rate_limits[key] and ahora - self.rate_limits[key][0] > 3600:
            self.rate_limits[key].popleft()
        
        # Verificar límite
        limite = self.limites_operacion.get(operacion, 5)
        if len(self.rate_limits[key]) >= limite:
            raise SecurityError(f"Rate limit excedido para {operacion}: {limite} operaciones por hora")
        
        # Verificar operaciones simultáneas
        operaciones_activas = len([op for op in self.operaciones_activas.values() if op['activa']])
        if operaciones_activas >= self.max_operaciones_simultaneas:
            raise SecurityError(f"Máximo de operaciones simultáneas excedido: {self.max_operaciones_simultaneas}")
        
        # Registrar operación
        self.rate_limits[key].append(ahora)
        operacion_id = f"{operacion}_{int(ahora)}"
        self.operaciones_activas[operacion_id] = {
            'inicio': ahora,
            'operacion': operacion,
            'usuario': usuario,
            'activa': True
        }
        
        return operacion_id
    
    def _finalizar_operacion(self, operacion_id: str):
        """Marcar operación como finalizada."""
        if operacion_id in self.operaciones_activas:
            self.operaciones_activas[operacion_id]['activa'] = False
            self.operaciones_activas[operacion_id]['fin'] = time.time()
    
    def _timeout_seguro(self, timeout_solicitado: int) -> int:
        """
        Calcular timeout seguro.
        
        Args:
            timeout_solicitado: Timeout solicitado por el usuario
            
        Returns:
            int: Timeout seguro limitado
        """
        max_timeout = self.config_seguridad['max_timeout']
        
        if timeout_solicitado <= 0:
            return 30  # Timeout mínimo
        
        if timeout_solicitado > max_timeout:
            self.logger.warning(f"Timeout reducido de {timeout_solicitado}s a {max_timeout}s por seguridad")
            return max_timeout
        
        return timeout_solicitado
```

---

## 🚨 CORRECCIÓN CRÍTICA #5: Manejo Seguro de Archivos Temporales

### Archivo a modificar: `escaneador_kali_real.py`

#### Reemplazar uso de tempfile:

```python
import tempfile
import stat

def _crear_archivo_temporal_seguro(self, contenido: str = None) -> str:
    """
    Crear archivo temporal con permisos seguros.
    
    Args:
        contenido: Contenido inicial del archivo
        
    Returns:
        str: Ruta del archivo temporal
    """
    try:
        # Crear archivo temporal con permisos restrictivos
        fd, ruta_temp = tempfile.mkstemp(
            prefix='ares_aegis_',
            suffix='.tmp',
            dir='/tmp',
            text=True
        )
        
        # Establecer permisos seguros (solo owner puede leer/escribir)
        os.fchmod(fd, stat.S_IRUSR | stat.S_IWUSR)
        
        if contenido:
            with os.fdopen(fd, 'w', encoding='utf-8') as f:
                f.write(contenido)
        else:
            os.close(fd)
        
        # Registrar para limpieza posterior
        self._registrar_archivo_temporal(ruta_temp)
        
        return ruta_temp
        
    except Exception as e:
        self.logger.error(f"Error creando archivo temporal: {e}")
        raise SecurityError("No se pudo crear archivo temporal seguro")

def _registrar_archivo_temporal(self, ruta: str):
    """Registrar archivo temporal para limpieza."""
    if not hasattr(self, '_archivos_temporales'):
        self._archivos_temporales = set()
    self._archivos_temporales.add(ruta)

def _limpiar_archivos_temporales(self):
    """Limpiar todos los archivos temporales creados."""
    if hasattr(self, '_archivos_temporales'):
        for ruta in self._archivos_temporales.copy():
            try:
                if os.path.exists(ruta):
                    # Sobrescribir contenido antes de eliminar
                    with open(ruta, 'w') as f:
                        f.write('0' * 1024)  # Sobrescribir con ceros
                    os.remove(ruta)
                self._archivos_temporales.remove(ruta)
            except Exception as e:
                self.logger.warning(f"Error eliminando archivo temporal {ruta}: {e}")

def __del__(self):
    """Destructor para limpiar archivos temporales."""
    try:
        self._limpiar_archivos_temporales()
    except:
        pass
```

---

## 🚨 CORRECCIÓN CRÍTICA #6: Validación de Configuración

### Archivo a modificar: `escaneador_kali_real.py`

#### Agregar validación estricta de configuración:

```python
def _validar_configuracion_escaneo(self, config: ConfiguracionEscaneo) -> ConfiguracionEscaneo:
    """
    Validar y sanitizar configuración de escaneo.
    
    Args:
        config: Configuración a validar
        
    Returns:
        ConfiguracionEscaneo: Configuración validada y segura
        
    Raises:
        SecurityError: Si la configuración es insegura
    """
    # Validar objetivo
    self._validar_objetivo_seguro(config.objetivo)
    
    # Validar puertos
    self._validar_puertos_seguro(config.puertos)
    
    # Validar timeout
    config.timeout = self._timeout_seguro(config.timeout)
    
    # Validar intensidad (T1-T5)
    if not isinstance(config.intensidad, int) or not 1 <= config.intensidad <= 5:
        raise SecurityError(f"Intensidad inválida: {config.intensidad}")
    
    # Validar max_threads
    if not isinstance(config.max_threads, int) or config.max_threads < 1:
        config.max_threads = 10
    elif config.max_threads > self.config_seguridad['max_threads']:
        config.max_threads = self.config_seguridad['max_threads']
        self.logger.warning(f"Max threads reducido a {config.max_threads}")
    
    # Validar scripts NSE
    if config.scripts_nse:
        config.scripts_nse = self._validar_scripts_nse(config.scripts_nse)
    
    return config

def _validar_scripts_nse(self, scripts: List[str]) -> List[str]:
    """
    Validar scripts NSE permitidos.
    
    Args:
        scripts: Lista de scripts solicitados
        
    Returns:
        List[str]: Scripts validados
    """
    scripts_permitidos = {
        'default', 'safe', 'vuln', 'exploit', 'discovery',
        'version', 'os-detection', 'service-detection'
    }
    
    scripts_validos = []
    for script in scripts:
        if not isinstance(script, str):
            continue
            
        script = script.strip().lower()
        
        # Verificar caracteres peligrosos
        if not re.match(r'^[a-z0-9\-]+$', script):
            self.logger.warning(f"Script NSE inválido ignorado: {script}")
            continue
        
        if script in scripts_permitidos:
            scripts_validos.append(script)
        else:
            self.logger.warning(f"Script NSE no permitido ignorado: {script}")
    
    return scripts_validos
```

---

## 🚨 CORRECCIÓN CRÍTICA #7: Error Handling Seguro

### Archivo a modificar: Ambos archivos

#### Reemplazar todos los bloques try/except:

```python
def _manejar_error_seguro(self, operacion: str, error: Exception, contexto: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Manejo seguro de errores sin exposición de información.
    
    Args:
        operacion: Nombre de la operación que falló
        error: Excepción capturada
        contexto: Contexto adicional (será censurado)
        
    Returns:
        Dict[str, Any]: Respuesta de error segura
    """
    # Generar ID único para el error
    error_id = hashlib.md5(f"{time.time()}{str(error)}".encode()).hexdigest()[:8]
    
    # Log interno detallado (para debugging)
    self.logger.error(f"Error {error_id} en {operacion}: {str(error)}", exc_info=True)
    
    # Clasificar tipo de error
    if isinstance(error, SecurityError):
        mensaje_usuario = "Operación denegada por políticas de seguridad"
        nivel = "SECURITY"
    elif isinstance(error, subprocess.TimeoutExpired):
        mensaje_usuario = "Operación excedió tiempo límite"
        nivel = "TIMEOUT"
    elif isinstance(error, PermissionError):
        mensaje_usuario = "Permisos insuficientes para la operación"
        nivel = "PERMISSION"
    elif isinstance(error, FileNotFoundError):
        mensaje_usuario = "Herramienta requerida no encontrada"
        nivel = "TOOL_MISSING"
    elif isinstance(error, (ConnectionError, OSError)):
        mensaje_usuario = "Error de conectividad"
        nivel = "NETWORK"
    else:
        mensaje_usuario = "Error interno del sistema"
        nivel = "INTERNAL"
    
    # Auditar error crítico
    if nivel in ["SECURITY", "PERMISSION"]:
        self._auditar_error_critico(error_id, operacion, nivel, str(error))
    
    # Respuesta segura al usuario
    return {
        'exito': False,
        'error': mensaje_usuario,
        'error_id': error_id,
        'nivel': nivel,
        'timestamp': datetime.datetime.now().isoformat(),
        'operacion': operacion
    }

def _auditar_error_critico(self, error_id: str, operacion: str, nivel: str, detalle: str):
    """Auditar errores críticos de seguridad."""
    evento_auditoria = {
        'tipo': 'ERROR_CRITICO',
        'error_id': error_id,
        'timestamp': datetime.datetime.now().isoformat(),
        'operacion': operacion,
        'nivel': nivel,
        'usuario': getpass.getuser(),
        'ip_origen': self._obtener_ip_local(),
        'detalle_hash': hashlib.sha256(detalle.encode()).hexdigest()
    }
    
    self._escribir_auditoria(evento_auditoria)
```

---

## 🔧 IMPLEMENTACIÓN PRÁCTICA

### Orden de Implementación Recomendado:

1. **Día 1**: Implementar validación universal de inputs
2. **Día 2**: Agregar sanitización de comandos  
3. **Día 3**: Implementar logging seguro
4. **Día 4**: Agregar rate limiting y timeouts seguros
5. **Día 5**: Implementar manejo seguro de archivos temporales
6. **Día 6**: Agregar validación de configuración
7. **Día 7**: Implementar error handling seguro y testing

### Testing de Seguridad:

```python
# Script de testing para validar correcciones
def test_seguridad_escaneador():
    """Tests de seguridad para validar correcciones."""
    
    # Test 1: Command injection
    try:
        escaneador._validar_objetivo_seguro("192.168.1.1; rm -rf /")
        assert False, "Debería rechazar command injection"
    except ValueError:
        print("✅ Test 1 pasado: Command injection bloqueado")
    
    # Test 2: Path traversal
    try:
        escaneador._validar_objetivo_seguro("../../../etc/passwd")
        assert False, "Debería rechazar path traversal"
    except ValueError:
        print("✅ Test 2 pasado: Path traversal bloqueado")
    
    # Test 3: Rate limiting
    try:
        for i in range(15):  # Exceder límite
            escaneador._verificar_rate_limit('escaneo_completo')
        assert False, "Debería aplicar rate limiting"
    except SecurityError:
        print("✅ Test 3 pasado: Rate limiting funcionando")
    
    print("🎉 Todos los tests de seguridad pasaron")
```

---

## 📊 VERIFICACIÓN POST-IMPLEMENTACIÓN

### Checklist de Validación:

- [ ] Validación universal de inputs implementada
- [ ] Sanitización de comandos activa
- [ ] Logging seguro sin exposición de datos
- [ ] Rate limiting funcionando
- [ ] Timeouts reducidos apropiadamente
- [ ] Archivos temporales con permisos seguros
- [ ] Error handling sin information disclosure
- [ ] Tests de seguridad pasando

### Métricas de Éxito:

- **0 vulnerabilidades críticas** en re-auditoría
- **Reducción 90%** en superficie de ataque
- **100% comandos** sanitizados antes de ejecución
- **Logs seguros** sin información sensible

---

*Estas correcciones deben implementarse inmediatamente antes de usar el escaneador en producción.*
